#include "ClangdIndexerImpl.h"

#include "ClangdIndex.h"
#include "ClangdIndexDataConsumer.h"
#include "../Path.h"
#include "../ClangdFileUtils.h"

#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Index/IndexingAction.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Timer.h"

#include <unordered_set>

namespace clang {
namespace clangd {

namespace {

bool isTimeStampChanged(ClangdIndexFile &File, const llvm::sys::fs::directory_entry& Entry) {
  auto Status = Entry.status();
  if (!Status)
    return true;
  if (!File.getLastIndexingTime())
    return true;

  auto ModifiedTime = Status->getLastModificationTime();
  auto Duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
      ModifiedTime.time_since_epoch());
  return *File.getLastIndexingTime() < Duration;
}

class TranslationUnitToBeIndexedCollector {
  bool CheckModified;
  ClangdIndex &Index;
  std::vector<std::string> PathsToBeIndexed;
  std::unordered_set<std::string> PathsToBeIndexedSet;

public:
  TranslationUnitToBeIndexedCollector(bool CheckModified, ClangdIndex &Index) : CheckModified(CheckModified), Index(Index) {
  }

  void visitPath(StringRef Path) {
    llvm::sys::fs::directory_entry Entry(Path);
    auto Status = Entry.status();
    if (!Status) {
      llvm::errs() << " Cannot stat file. Nothing to do. " << "\n";
      return;
    }
    llvm::sys::fs::file_type Type = Status->type();
    if (Type == llvm::sys::fs::file_type::directory_file)
      visitFolder(Path, CheckModified);
    else
      visitFile(Entry, CheckModified);
  }

  std::vector<std::string> takePaths() {
    return std::move(PathsToBeIndexed);
  }

private:

  void addFile(StringRef File) {
    if (PathsToBeIndexedSet.find(File) == PathsToBeIndexedSet.end()) {
      PathsToBeIndexedSet.insert(File);
      PathsToBeIndexed.push_back(File);
    }
  }

  void visitFile(llvm::sys::fs::directory_entry FileEntry, bool CheckModified) {
    StringRef File = FileEntry.path();
    assert(!File.empty());
    llvm::errs() << llvm::formatv("Visiting {0}\n", File.str());

    bool IsSourceFilePath = isSourceFilePath(File);
    bool IsHeaderFilePath = false;
    if (!IsSourceFilePath)
      IsHeaderFilePath = isHeaderFilePath(File);

    if (!IsSourceFilePath && !IsHeaderFilePath) {
      llvm::errs() << " Not a C-family file. Nothing to do. " << "\n";
      return;
    }

    std::unique_ptr<ClangdIndexFile> ExistingFile = Index.getFile(File);
    if (ExistingFile) {
      if (CheckModified) {
        if (!isTimeStampChanged(*ExistingFile, FileEntry)) {
          // TODO: Check content hash
          llvm::errs() << " Timestamp the same for " << File.str() << "\n";
          return;
        }

        llvm::errs() << " Timestamp *modified* for " << File.str() << "\n";

        // Visit all the dependent files
        class DependentsVisitor : public ClangdIndexFile::DependentVisitor {
          TranslationUnitToBeIndexedCollector &Collector;
        public:
          DependentsVisitor(
              TranslationUnitToBeIndexedCollector &Collector) :
                Collector(Collector) {
          }
          virtual ClangdIndexFile::NodeVisitResult VisitDependent(ClangdIndexFile& File) override {
            StringRef Path = File.getPath();
            llvm::errs() << " Considering dependent : " << Path << "\n";
            llvm::sys::fs::directory_entry Entry(Path);
            auto Status = Entry.status();
            if (!Status) {
              llvm::errs() << " Cannot stat file. Nothing to do. " << "\n";
              return ClangdIndexFile::NodeVisitResult::CONTINUE;
            }
            Collector.visitFile(Entry, false);
            return ClangdIndexFile::NodeVisitResult::CONTINUE;
          }
        };
        DependentsVisitor V(*this);
        ExistingFile->visitDependentFiles(V);
      }

      Index.getStorage().startWrite();
      // In the case of a header, we especially need to call onChange
      // before we start indexing the including source files because
      // that's how we know we need to index the content of the header (We
      // check the presence of symbols and onChange clears them).
      ExistingFile->onChange();
      Index.getStorage().endWrite();
    }

    // Header content is indexed when a source file that includes it is being
    // indexed.
    if (IsSourceFilePath)
      addFile(File);
  }

  void visitFolder(StringRef Folder, bool CheckModified) {
    assert(!Folder.empty());
    std::error_code EC;
    for (llvm::sys::fs::directory_iterator I(Folder.str(), EC), E; I != E;
        I.increment(EC)) {
      if (EC)
        continue;
      const llvm::sys::fs::directory_entry& Entry = *I;
      auto Status = Entry.status();
      if (!Status)
        continue;
      llvm::sys::fs::file_type Type = Status->type();
      if (Type == llvm::sys::fs::file_type::directory_file)
        visitFolder(Entry.path(), CheckModified);
      else
        visitFile(Entry, CheckModified);
    }
  }

};

// Stores the "included by" -> "included file" relationship
void addInclusion(ClangdIndexHeaderInclusion& Inclusion, ClangdIndexFile& IncludedByFile) {
  auto FirstInclusion = IncludedByFile.getFirstInclusion();
  IncludedByFile.setFirstInclusion(Inclusion.getRecord());
  if (FirstInclusion) {
    Inclusion.setNextInclusion(FirstInclusion->getRecord());
    FirstInclusion->setPrevInclusion(Inclusion.getRecord());
  }
}

bool includedByExists(ClangdIndexFile &IncludedFile, ClangdIndexFile &IncludedByFile) {
  auto IncludedBySearch = IncludedFile.getFirstIncludedBy();
  while (IncludedBySearch) {
    auto IncludedByFileSearch = IncludedBySearch->getIncludedBy();
    if (IncludedByFile.getPath().compare(IncludedByFileSearch->getPath()) == 0)
      return true;

    IncludedBySearch = IncludedBySearch->getNextIncludeBy();
  }
  return false;
}

void handleInclusions(ASTUnit &Unit, ClangdIndexFile &IndexFile, ClangdIndex &Index) {
  // Handle includes
  SourceManager &SM = Unit.getSourceManager();
  SmallVector<SourceLocation, 10> InclusionStack;
  const unsigned n =  SM.local_sloc_entry_size();
  for (unsigned i = 0 ; i < n ; ++i) {
    bool Invalid = false;
    const SrcMgr::SLocEntry &SL = SM.getLocalSLocEntry(i, &Invalid);

    if (!SL.isFile() || Invalid)
      continue;

    const SrcMgr::FileInfo &FI = SL.getFile();
    if (FI.getIncludeLoc().isInvalid() || !FI.getContentCache()->OrigEntry)
      continue;

    StringRef FilePath = FI.getContentCache()->OrigEntry->tryGetRealPathName();
    //Probably the included file doesn't exist?
    if (FilePath.empty())
      continue;

    SourceLocation L = FI.getIncludeLoc();
    // Build the inclusion stack.
    InclusionStack.clear();
    while (L.isValid()) {
      PresumedLoc PLoc = SM.getPresumedLoc(L);
      InclusionStack.push_back(L);
      L = PLoc.isValid()? PLoc.getIncludeLoc() : SourceLocation();
    }

    auto IncludedByEntry = SM.getFileEntryForID(SM.getFileID(InclusionStack.front()));
    if (!IncludedByEntry) {
      llvm::errs() << llvm::formatv("File including \"{0}\" does not exist.\n", FilePath);
      continue;
    }
    StringRef IncludedByName = IncludedByEntry->tryGetRealPathName();
    if (IncludedByName.empty()) {
      llvm::errs() << llvm::formatv("File including \"{0}\" does not exist.\n", FilePath);
      continue;
    }

    auto IncludedByFileFromIndex = Index.getFile(IncludedByName);
    ClangdIndexFile &IncludedByFile = InclusionStack.size() == 1 ? IndexFile : *IncludedByFileFromIndex;

    // Store the included file -> included by relationship
    auto IncludedFile = Index.getFile(FilePath);
    if (!IncludedFile) {
      IncludedFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), FilePath, Index);
      Index.addFile(*IncludedFile);
    }

    if (!includedByExists(*IncludedFile, IncludedByFile)) {
      auto Inclusion = llvm::make_unique<ClangdIndexHeaderInclusion>(Index.getStorage(), IncludedByFile, *IncludedFile, Index);
      auto FirstInclusion = IncludedFile->getFirstIncludedBy();
      IncludedFile->setFirstIncludedBy(Inclusion->getRecord());
      if (FirstInclusion) {
        Inclusion->setNextIncludedBy(FirstInclusion->getRecord());
        FirstInclusion->setPrevIncludedBy(Inclusion->getRecord());
      }
      addInclusion(*Inclusion, IncludedByFile);
    }
  }
}
}

ClangdIndexerImpl::ClangdIndexerImpl(std::string RootPath, GlobalCompilationDatabase &CDB, ClangdIndexerOptions Opts) :
    RootPath(RootPath), CDB(CDB), Opts(Opts) {
  assert(!RootPath.empty());
  if (RootPath.empty())
    return;

  SmallString<32> Filename(RootPath);
  llvm::sys::path::append(Filename, "clangd.index");
  // TODO, check version, etc
  IsFromScratch = !llvm::sys::fs::exists(Filename);
  Index = std::make_shared<ClangdIndex>(Filename.str());
  CDB.setIndex(Index);
}

void ClangdIndexerImpl::onFileEvent(FileEvent Event) {
  assert(Index);
  switch (Event.type) {
  case FileChangeType::Created:
  case FileChangeType::Changed:
  case FileChangeType::Deleted:
    TranslationUnitToBeIndexedCollector C(true, *Index);
    C.visitPath(Event.Path);
    auto FilesToIndex = C.takePaths();

    if (Event.type == FileChangeType::Deleted) {
      auto FileInIndex = Index->getFile(Event.Path);
      if (!FileInIndex) {
        llvm::errs() << " Unknown to index. Nothing to do. " << "\n";
        return;
      }
      Index->getStorage().startWrite();
      FileInIndex->free();
      Index->getStorage().endWrite();
      // Don't index the file that just got deleted but re-index its dependents.
      std::remove(std::begin(FilesToIndex), std::end(FilesToIndex), Event.Path);
    }

    indexFiles(FilesToIndex);
  }
}

void ClangdIndexerImpl::indexFile (StringRef File) {
  llvm::errs() << " Indexing " << File.str() << "\n";
  assert(!isHeaderFilePath(File) && "Only source files should be indexed.");

  llvm::sys::fs::directory_entry Entry(File);
  auto Status = Entry.status();
  if (!Status) {
    llvm::errs() << " Cannot stat file. Skipping file. " << "\n";
    return;
  }
  auto Commands = CDB.getCompileCommand(File, false);
  if (!Commands && Opts.IncludeCDBFilesOnly) {
    llvm::errs() << " No entry in compilation database. Skipping file. " << "\n";
    return;
  }

  Index->getStorage().startWrite();
  std::unique_ptr<ClangdIndexFile> IndexFile = Index->getFile(File);
  if (!IndexFile) {
    IndexFile = llvm::make_unique<ClangdIndexFile>(Index->getStorage(), File.str(), *Index);
    Index->addFile(*IndexFile);
  }

  // Get the time so we know when we last indexed the file.
  auto IndexingTimePoint = std::chrono::system_clock::now();
  auto IndexingTimePointDurationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(IndexingTimePoint.time_since_epoch());
  // We only save the time stamp after indexing, that way if indexing is
  // cancelled midway, the file will still be re-indexed later.

  auto DataConsumer = std::make_shared<ClangdIndexDataConsumer>(llvm::errs(), *Index, *IndexFile);
  index::IndexingOptions IndexOpts;
  IndexOpts.SystemSymbolFilter = index::IndexingOptions::SystemSymbolFilterKind::All;
  IndexOpts.IndexFunctionLocals = false;
  std::unique_ptr<FrontendAction> IndexAction;
  IndexAction = index::createIndexingAction(DataConsumer, IndexOpts,
                                     /*WrappedAction=*/nullptr);

  IntrusiveRefCntPtr<DiagnosticsEngine> Diags =
      CompilerInstance::createDiagnostics(new DiagnosticOptions);
  // chdir. This is thread hostile.
  if (Commands)
    llvm::sys::fs::set_current_path(Commands->Directory);

  if (!Commands) {
    // Add a fake command line if we know nothing.
    Commands = CDB.getFallbackCommand(File);
  }

  // Inject the resource dir.
  // FIXME: Don't overwrite it if it's already there.
  static int Dummy; // Just an address in this process.
  std::string ResourceDir =
      CompilerInvocation::GetResourcesPath("clangd", (void *)&Dummy);
  Commands->CommandLine.push_back("-resource-dir=" + ResourceDir);
  std::vector<const char *> ArgStrs;
  for (const auto &S : Commands->CommandLine)
    ArgStrs.push_back(S.c_str());

  auto CInvok = createInvocationFromCommandLine(ArgStrs, Diags);
  if (!CInvok)
    return;
  auto PCHContainerOps = std::make_shared<PCHContainerOperations>();
  std::unique_ptr<ASTUnit> Unit(ASTUnit::LoadFromCompilerInvocationAction(
      std::move(CInvok), PCHContainerOps, Diags, IndexAction.get()));

  handleInclusions(*Unit, *IndexFile, *Index);

  IndexFile->setLastIndexingTime(IndexingTimePointDurationNs);

  class SetTimeStampOnInclusionsVisitor : public ClangdIndexFile::InclusionVisitor {
    std::chrono::nanoseconds IndexingTime;
  public:
    SetTimeStampOnInclusionsVisitor(std::chrono::nanoseconds IndexingTime) : IndexingTime(IndexingTime) {}
    virtual ClangdIndexFile::NodeVisitResult VisitInclusion(ClangdIndexFile& File) {
      // Whichever headers we haven't indexed before, we now have.
      // It's possible that the header didn't contain any occurrences but it's
      // considered indexed regardless otherwise next time we check for this
      // header's timestamp, we will think it's not indexed and we will index all
      // its dependents as well.
      auto Path = File.getPath();
      if (!File.getLastIndexingTime()) {
        File.setLastIndexingTime(IndexingTime);
      }
      return ClangdIndexFile::NodeVisitResult::CONTINUE;
    }
  };
  SetTimeStampOnInclusionsVisitor V(IndexingTimePointDurationNs);
  IndexFile->visitInclusions(V);
  Index->getStorage().endWrite();
}

void ClangdIndexerImpl::indexFiles(
    const std::vector<std::string>& FilesToIndex) {
  llvm::errs() << llvm::format("Indexing %u source files.", FilesToIndex.size()) << "\n";
  unsigned I = 1;
  for (auto TU : FilesToIndex) {
    llvm::errs() << llvm::format("(%u/%u) ", I, FilesToIndex.size());
    indexFile(TU);
    I++;
  }
}

void ClangdIndexerImpl::indexRoot() {
  assert(Index);
  auto IndexTotalTimer = llvm::Timer("index time", "Indexing Total Time");
  IndexTotalTimer.startTimer();

  TranslationUnitToBeIndexedCollector C(!IsFromScratch, *Index);
  C.visitPath(RootPath);
  auto FilesToIndex = C.takePaths();
  indexFiles(FilesToIndex);
  IndexTotalTimer.stopTimer();
  Index->flush();
}

void ClangdIndexerImpl::reindex() {
  SmallString<32> Filename(RootPath);
  llvm::sys::path::append(Filename, "clangd.index");
  if (llvm::sys::fs::exists(Filename)) {
    llvm::sys::fs::remove_directories(Filename);
  }
  Index = std::make_shared<ClangdIndex>(Filename.str());
  CDB.setIndex(Index);

  IsFromScratch = true;
  indexRoot();
}

void ClangdIndexerImpl::printStats() {
  unsigned NumSymbols, NumOccurrences = 0;
  Index->foreachSymbols([&NumSymbols, &NumOccurrences](ClangdIndexSymbol &Sym){
    NumSymbols++;
    Sym.foreachOccurrence(llvm::None, [&NumOccurrences](ClangdIndexOccurrence &Occurrence){
      NumOccurrences++;
      return true;
    });
    return true;
  });
  llvm::errs() << "Index stats:\n";
  llvm::errs().indent(2) << llvm::format("Symbols: %u\n", NumSymbols);
  llvm::errs().indent(2) << llvm::format("Occurrences: %u\n", NumOccurrences);
}

namespace {

class ClangdIndexDataOccurrenceAdapter : public ClangdIndexDataOccurrence {
  ClangdIndexOccurrence &Occurrence;
public:
  ClangdIndexDataOccurrenceAdapter(ClangdIndexOccurrence &Occurrence) : Occurrence(Occurrence) {

  }
  std::string getPath() override { return Occurrence.getPath(); }
  uint32_t getStartOffset(SourceManager &SM) override { return Occurrence.getLocStart(); }
  uint32_t getEndOffset(SourceManager &SM) override { return Occurrence.getLocEnd(); }
};

class ClangdIndexDataDefinitionOccurrenceAdapter: public ClangdIndexDataDefinitionOccurrence,
    public ClangdIndexDataOccurrenceAdapter {
  ClangdIndexDefinitionOccurrence &Occurrence;
public:
  ClangdIndexDataDefinitionOccurrenceAdapter(ClangdIndexDefinitionOccurrence &Occurrence) :
      ClangdIndexDataOccurrenceAdapter(Occurrence),
      Occurrence(Occurrence) {
  }

  OccurrenceType getKind() const override { return OccurrenceType::DEFINITION_OCCURRENCE; }
  std::string getPath() override { return ClangdIndexDataOccurrenceAdapter::getPath(); }
  uint32_t getStartOffset(SourceManager &SM) override { return ClangdIndexDataOccurrenceAdapter::getStartOffset(SM); }
  uint32_t getEndOffset(SourceManager &SM) override { return ClangdIndexDataOccurrenceAdapter::getEndOffset(SM); }

  uint32_t getDefStartOffset(SourceManager &SM) override {
    return Occurrence.getDefLocStart();
  }

  uint32_t getDefEndOffset(SourceManager &SM) override {
    return Occurrence.getDefLocEnd();
  }
};

class ClangdIndexDataSymbolAdapter : public ClangdIndexDataSymbol {
  ClangdIndexSymbol &Symbol;
public:
  ClangdIndexDataSymbolAdapter(ClangdIndexSymbol &Symbol) : Symbol(Symbol) {
  }

  index::SymbolKind getKind() override {
    return Symbol.getKind();
  }
  std::string getName() override {
    return Symbol.getName();
  }
  std::string getQualifier() override {
    return Symbol.getQualifier();
  }

  std::string getUsr() override {
    return Symbol.getUsr();
  }

  void foreachOccurrence(llvm::Optional<index::SymbolRoleSet> RolesFilter, llvm::function_ref<bool(ClangdIndexDataOccurrence&)> Receiver) override {
    Symbol.foreachOccurrence(RolesFilter, [&Receiver](ClangdIndexOccurrence &Occurrence) {
      if (ClangdIndexDefinitionOccurrence * DefOccurrence = dyn_cast<ClangdIndexDefinitionOccurrence>(&Occurrence)) {
        ClangdIndexDataDefinitionOccurrenceAdapter DataOccurrence(*DefOccurrence);
        return Receiver(static_cast<ClangdIndexDataDefinitionOccurrence&>(DataOccurrence));
      } else {
        ClangdIndexDataOccurrenceAdapter DataOccurrence(Occurrence);
        return Receiver(DataOccurrence);
      }
    });
  }
};

}

void ClangdIndexerImpl::foreachSymbols(StringRef Query, llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) {
  Index->foreachSymbols(Query, [&Receiver](ClangdIndexSymbol &Symbol) {
    ClangdIndexDataSymbolAdapter Sym(Symbol);
    return Receiver(Sym);
  });
}

void ClangdIndexerImpl::foreachSymbols(const USR &Usr, llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) {
  Index->foreachSymbols(Usr, [&Receiver](ClangdIndexSymbol &Symbol) {
    ClangdIndexDataSymbolAdapter Sym(Symbol);
    return Receiver(Sym);
  });
}

void ClangdIndexerImpl::dumpIncludedBy(StringRef File) {
  auto IndexFile = Index->getFile(File);
  if (!IndexFile) {
    llvm::errs() << " Unknown to index. Nothing to do. " << "\n";
    return;
  }

  class PrintDependentsVisitor : public ClangdIndexFile::DependentVisitor {
    int Level = 0;
  public:
    virtual void EnterFile(ClangdIndexFile&) override {
      Level++;
    }
    virtual void LeaveFile(ClangdIndexFile&) override {
      Level--;
    }

    virtual ClangdIndexFile::NodeVisitResult VisitDependent(ClangdIndexFile& File) override {
      llvm::errs().indent(Level * 2);
      llvm::errs() << File.getPath() << "\n";
      return ClangdIndexFile::NodeVisitResult::CONTINUE;
    }
  };
  PrintDependentsVisitor V;
  IndexFile->visitDependentFiles(V);
}

void ClangdIndexerImpl::dumpInclusions(StringRef File) {
  auto IndexFile = Index->getFile(File);
  if (!IndexFile) {
    llvm::errs() << " Unknown to index. Nothing to do. " << "\n";
    return;
  }

  class PrintInclusionsVisitor : public ClangdIndexFile::InclusionVisitor {
    int Level = 0;
  public:
    virtual void EnterFile(ClangdIndexFile&) override {
      Level++;
    }
    virtual void LeaveFile(ClangdIndexFile&) override {
      Level--;
    }

    virtual ClangdIndexFile::NodeVisitResult VisitInclusion(ClangdIndexFile& File) override {
      llvm::errs().indent(Level * 2);
      llvm::errs() << File.getPath() << "\n";
      return ClangdIndexFile::NodeVisitResult::CONTINUE;
    }
  };
  PrintInclusionsVisitor V;
  IndexFile->visitInclusions(V);
}

} /* namespace clangd */
} /* namespace clang */
