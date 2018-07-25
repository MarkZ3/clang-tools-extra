//===--- ClangdServer.cpp - Main clangd server code --------------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#include "ClangdServer.h"
#include "ClangdFileUtils.h"
#include "CodeComplete.h"
#include "FindSymbols.h"
#include "Headers.h"
#include "SourceCode.h"
#include "XRefs.h"
#include "index/ClangdIndexDataConsumer.h"
#include "index/ClangdIndexerImpl.h"
#include "index/Merge.h"

#include "clang/Format/Format.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Index/IndexingAction.h"
#include "clang/Index/IndexDataConsumer.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Refactoring/RefactoringResultConsumer.h"
#include "clang/Tooling/Refactoring/Rename/RenamingAction.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Timer.h"

#include <future>

using namespace clang;
using namespace clang::clangd;

namespace {

void ignoreError(llvm::Error Err) {
  handleAllErrors(std::move(Err), [](const llvm::ErrorInfoBase &) {});
}

std::string getStandardResourceDir() {
  static int Dummy; // Just an address in this process.
  return CompilerInvocation::GetResourcesPath("clangd", (void *)&Dummy);
}

class RefactoringResultCollector final
    : public tooling::RefactoringResultConsumer {
public:
  void handleError(llvm::Error Err) override {
    assert(!Result.hasValue());
    // FIXME: figure out a way to return better message for DiagnosticError.
    // clangd uses llvm::toString to convert the Err to string, however, for
    // DiagnosticError, only "clang diagnostic" will be generated.
    Result = std::move(Err);
  }

  // Using the handle(SymbolOccurrences) from parent class.
  using tooling::RefactoringResultConsumer::handle;

  void handle(tooling::AtomicChanges SourceReplacements) override {
    assert(!Result.hasValue());
    Result = std::move(SourceReplacements);
  }

  Optional<Expected<tooling::AtomicChanges>> Result;
};

} // namespace

IntrusiveRefCntPtr<vfs::FileSystem> RealFileSystemProvider::getFileSystem() {
  return vfs::getRealFileSystem();
}

ClangdServer::Options ClangdServer::optsForTest() {
  ClangdServer::Options Opts;
  Opts.UpdateDebounce = std::chrono::steady_clock::duration::zero(); // Faster!
  Opts.StorePreamblesInMemory = true;
  Opts.AsyncThreadsCount = 4; // Consistent!
  return Opts;
}

ClangdServer::ClangdServer(GlobalCompilationDatabase &CDB,
                           FileSystemProvider &FSProvider,
                           DiagnosticsConsumer &DiagConsumer,
                           const Options &Opts,
                           const ClangdIndexerOptions &IndexerOptions)
    : CDB(CDB), DiagConsumer(DiagConsumer), FSProvider(FSProvider),
      ResourceDir(Opts.ResourceDir ? Opts.ResourceDir->str()
                                   : getStandardResourceDir()),
      FileIdx(Opts.BuildDynamicSymbolIndex ? new FileIndex(Opts.URISchemes)
                                           : nullptr),
      PCHs(std::make_shared<PCHContainerOperations>()),
      // Pass a callback into `WorkScheduler` to extract symbols from a newly
      // parsed file and rebuild the file index synchronously each time an AST
      // is parsed.
      // FIXME(ioeric): this can be slow and we may be able to index on less
      // critical paths.
      WorkScheduler(
          Opts.AsyncThreadsCount, Opts.StorePreamblesInMemory,
          FileIdx
              ? [this](PathRef Path, ASTContext &AST,
                       std::shared_ptr<Preprocessor>
                           PP) { FileIdx->update(Path, &AST, std::move(PP)); }
              : PreambleParsedCallback(),
          Opts.UpdateDebounce, Opts.RetentionPolicy),
          IndexerOptions(IndexerOptions) {
  if (FileIdx && Opts.StaticIndex) {
    MergedIndex = mergeIndex(FileIdx.get(), Opts.StaticIndex);
    Index = MergedIndex.get();
  } else if (FileIdx)
    Index = FileIdx.get();
  else if (Opts.StaticIndex)
    Index = Opts.StaticIndex;
  else
    Index = nullptr;
}

void ClangdServer::setRootPath(PathRef RootPath) {
  auto FS = FSProvider.getFileSystem();
  std::string NewRootPath = llvm::sys::path::convert_to_slash(
      RootPath, llvm::sys::path::Style::posix);
  SmallString<256> RootPathRemoveDots = StringRef(NewRootPath);
  llvm::sys::path::remove_dots(RootPathRemoveDots, true);

  auto Status = FS->status(RootPathRemoveDots);
  if (!Status)
    log("Failed to get status for RootPath " + RootPathRemoveDots + ": " +
        Status.getError().message());
  else if (Status->isDirectory())
    this->RootPath = RootPathRemoveDots.str();
  else
    log("The provided RootPath " + RootPath + " is not a directory.");

  if (!this->RootPath)
    return;

  assert (!Indexer);
  auto ClangIndexer = std::make_shared<ClangdIndexerImpl>(RootPath.str(), CDB, IndexerOptions);
  Indexer = ClangIndexer;
  IndexDataProvider = ClangIndexer;
  assert(Indexer && IndexDataProvider);
  Indexer->indexRoot();
}

void ClangdServer::addDocument(PathRef File, StringRef Contents,
                               WantDiagnostics WantDiags) {
  DocVersion Version = ++InternalVersion[File];
  ParseInputs Inputs = {getCompileCommand(File), FSProvider.getFileSystem(),
                        Contents.str()};

  Path FileStr = File.str();
  WorkScheduler.update(File, std::move(Inputs), WantDiags,
                       [this, FileStr, Version](std::vector<Diag> Diags) {
                         consumeDiagnostics(FileStr, Version, std::move(Diags));
                       });
}

void ClangdServer::removeDocument(PathRef File) {
  ++InternalVersion[File];
  WorkScheduler.remove(File);
}

void ClangdServer::codeComplete(PathRef File, Position Pos,
                                const clangd::CodeCompleteOptions &Opts,
                                Callback<CodeCompleteResult> CB) {
  // Copy completion options for passing them to async task handler.
  auto CodeCompleteOpts = Opts;
  if (!CodeCompleteOpts.Index) // Respect overridden index.
    CodeCompleteOpts.Index = Index;

  // Copy PCHs to avoid accessing this->PCHs concurrently
  std::shared_ptr<PCHContainerOperations> PCHs = this->PCHs;
  auto FS = FSProvider.getFileSystem();
  auto Task = [PCHs, Pos, FS,
               CodeCompleteOpts](Path File, Callback<CodeCompleteResult> CB,
                                 llvm::Expected<InputsAndPreamble> IP) {
    if (!IP)
      return CB(IP.takeError());

    auto PreambleData = IP->Preamble;

    // FIXME(ibiryukov): even if Preamble is non-null, we may want to check
    // both the old and the new version in case only one of them matches.
    CodeCompleteResult Result = clangd::codeComplete(
        File, IP->Command, PreambleData ? &PreambleData->Preamble : nullptr,
        PreambleData ? PreambleData->Includes : IncludeStructure(),
        IP->Contents, Pos, FS, PCHs, CodeCompleteOpts);
    CB(std::move(Result));
  };

  WorkScheduler.runWithPreamble("CodeComplete", File,
                                Bind(Task, File.str(), std::move(CB)));
}

void ClangdServer::signatureHelp(PathRef File, Position Pos,
                                 Callback<SignatureHelp> CB) {

  auto PCHs = this->PCHs;
  auto FS = FSProvider.getFileSystem();
  auto Action = [Pos, FS, PCHs](Path File, Callback<SignatureHelp> CB,
                                llvm::Expected<InputsAndPreamble> IP) {
    if (!IP)
      return CB(IP.takeError());

    auto PreambleData = IP->Preamble;
    CB(clangd::signatureHelp(File, IP->Command,
                             PreambleData ? &PreambleData->Preamble : nullptr,
                             IP->Contents, Pos, FS, PCHs));
  };

  WorkScheduler.runWithPreamble("SignatureHelp", File,
                                Bind(Action, File.str(), std::move(CB)));
}

llvm::Expected<tooling::Replacements>
ClangdServer::formatRange(StringRef Code, PathRef File, Range Rng) {
  llvm::Expected<size_t> Begin = positionToOffset(Code, Rng.start);
  if (!Begin)
    return Begin.takeError();
  llvm::Expected<size_t> End = positionToOffset(Code, Rng.end);
  if (!End)
    return End.takeError();
  return formatCode(Code, File, {tooling::Range(*Begin, *End - *Begin)});
}

llvm::Expected<tooling::Replacements> ClangdServer::formatFile(StringRef Code,
                                                               PathRef File) {
  // Format everything.
  return formatCode(Code, File, {tooling::Range(0, Code.size())});
}

llvm::Expected<tooling::Replacements>
ClangdServer::formatOnType(StringRef Code, PathRef File, Position Pos) {
  // Look for the previous opening brace from the character position and
  // format starting from there.
  llvm::Expected<size_t> CursorPos = positionToOffset(Code, Pos);
  if (!CursorPos)
    return CursorPos.takeError();
  size_t PreviousLBracePos = StringRef(Code).find_last_of('{', *CursorPos);
  if (PreviousLBracePos == StringRef::npos)
    PreviousLBracePos = *CursorPos;
  size_t Len = *CursorPos - PreviousLBracePos;

  return formatCode(Code, File, {tooling::Range(PreviousLBracePos, Len)});
}

void ClangdServer::rename(PathRef File, Position Pos, llvm::StringRef NewName,
                          Callback<std::vector<tooling::Replacement>> CB) {
  auto Action = [Pos](Path File, std::string NewName,
                      Callback<std::vector<tooling::Replacement>> CB,
                      Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    auto &AST = InpAST->AST;

    RefactoringResultCollector ResultCollector;
    const SourceManager &SourceMgr = AST.getASTContext().getSourceManager();
    SourceLocation SourceLocationBeg =
        clangd::getBeginningOfIdentifier(AST, Pos, SourceMgr.getMainFileID());
    tooling::RefactoringRuleContext Context(
        AST.getASTContext().getSourceManager());
    Context.setASTContext(AST.getASTContext());
    auto Rename = clang::tooling::RenameOccurrences::initiate(
        Context, SourceRange(SourceLocationBeg), NewName);
    if (!Rename)
      return CB(Rename.takeError());

    Rename->invoke(ResultCollector, Context);

    assert(ResultCollector.Result.hasValue());
    if (!ResultCollector.Result.getValue())
      return CB(ResultCollector.Result->takeError());

    std::vector<tooling::Replacement> Replacements;
    for (const tooling::AtomicChange &Change : ResultCollector.Result->get()) {
      tooling::Replacements ChangeReps = Change.getReplacements();
      for (const auto &Rep : ChangeReps) {
        // FIXME: Right now we only support renaming the main file, so we
        // drop replacements not for the main file. In the future, we might
        // consider to support:
        //   * rename in any included header
        //   * rename only in the "main" header
        //   * provide an error if there are symbols we won't rename (e.g.
        //     std::vector)
        //   * rename globally in project
        //   * rename in open files
        if (Rep.getFilePath() == File)
          Replacements.push_back(Rep);
      }
    }
    return CB(std::move(Replacements));
  };

  WorkScheduler.runWithAST(
      "Rename", File, Bind(Action, File.str(), NewName.str(), std::move(CB)));
}

void ClangdServer::dumpAST(PathRef File,
                           llvm::unique_function<void(std::string)> Callback) {
  auto Action = [](decltype(Callback) Callback,
                   llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST) {
      ignoreError(InpAST.takeError());
      return Callback("<no-ast>");
    }
    std::string Result;

    llvm::raw_string_ostream ResultOS(Result);
    clangd::dumpAST(InpAST->AST, ResultOS);
    ResultOS.flush();

    Callback(Result);
  };

  WorkScheduler.runWithAST("DumpAST", File, Bind(Action, std::move(Callback)));
}

void ClangdServer::findDefinitions(PathRef File, Position Pos,
                                   Callback<std::vector<Location>> CB) {
  auto Action = [Pos, this](Callback<std::vector<Location>> CB,
                            llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    CB(clangd::findDefinitions(InpAST->AST, Pos, IndexDataProvider, Index));
  };

  WorkScheduler.runWithAST("Definitions", File, Bind(Action, std::move(CB)));
}

llvm::Optional<Path> ClangdServer::switchSourceHeader(PathRef Path) {
  bool IsSource = isSourceFilePath(Path);
  bool IsHeader = isHeaderFilePath(Path);

  // We can only switch between the known extensions.
  if (!IsSource && !IsHeader)
    return llvm::None;

  // Array to lookup extensions for the switch. An opposite of where original
  // extension was found.
  ArrayRef<StringRef> NewExts;
  if (IsSource)
    NewExts = getHeaderExtensions();
  else
    NewExts = getSourceExtensions();

  // Storage for the new path.
  SmallString<128> NewPath = StringRef(Path);

  // Instance of vfs::FileSystem, used for file existence checks.
  auto FS = FSProvider.getFileSystem();

  // Loop through switched extension candidates.
  for (StringRef NewExt : NewExts) {
    llvm::sys::path::replace_extension(NewPath, NewExt);
    if (FS->exists(NewPath))
      return NewPath.str().str(); // First str() to convert from SmallString to
                                  // StringRef, second to convert from StringRef
                                  // to std::string

    // Also check NewExt in upper-case, just in case.
    llvm::sys::path::replace_extension(NewPath, NewExt.upper());
    if (FS->exists(NewPath))
      return NewPath.str().str();
  }

  return llvm::None;
}

llvm::Expected<tooling::Replacements>
ClangdServer::formatCode(llvm::StringRef Code, PathRef File,
                         ArrayRef<tooling::Range> Ranges) {
  // Call clang-format.
  auto FS = FSProvider.getFileSystem();
  auto Style = format::getStyle(format::DefaultFormatStyle, File,
                                format::DefaultFallbackStyle, Code, FS.get());
  if (!Style)
    return Style.takeError();

  tooling::Replacements IncludeReplaces =
      format::sortIncludes(*Style, Code, Ranges, File);
  auto Changed = tooling::applyAllReplacements(Code, IncludeReplaces);
  if (!Changed)
    return Changed.takeError();

  return IncludeReplaces.merge(format::reformat(
      Style.get(), *Changed,
      tooling::calculateRangesAfterReplacements(IncludeReplaces, Ranges),
      File));
}

void ClangdServer::findDocumentHighlights(
    PathRef File, Position Pos, Callback<std::vector<DocumentHighlight>> CB) {
  auto Action = [Pos](Callback<std::vector<DocumentHighlight>> CB,
                      llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    CB(clangd::findDocumentHighlights(InpAST->AST, Pos));
  };

  WorkScheduler.runWithAST("Highlights", File, Bind(Action, std::move(CB)));
}

void ClangdServer::findHover(PathRef File, Position Pos,
                             Callback<llvm::Optional<Hover>> CB) {
  auto Action = [Pos](Callback<llvm::Optional<Hover>> CB,
                      llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    CB(clangd::getHover(InpAST->AST, Pos));
  };

  WorkScheduler.runWithAST("Hover", File, Bind(Action, std::move(CB)));
}

void ClangdServer::consumeDiagnostics(PathRef File, DocVersion Version,
                                      std::vector<Diag> Diags) {
  // We need to serialize access to resulting diagnostics to avoid calling
  // `onDiagnosticsReady` in the wrong order.
  std::lock_guard<std::mutex> DiagsLock(DiagnosticsMutex);
  DocVersion &LastReportedDiagsVersion = ReportedDiagnosticVersions[File];

  // FIXME(ibiryukov): get rid of '<' comparison here. In the current
  // implementation diagnostics will not be reported after version counters'
  // overflow. This should not happen in practice, since DocVersion is a
  // 64-bit unsigned integer.
  if (Version < LastReportedDiagsVersion)
    return;
  LastReportedDiagsVersion = Version;

  DiagConsumer.onDiagnosticsReady(File, std::move(Diags));
}

tooling::CompileCommand ClangdServer::getCompileCommand(PathRef File) {
  llvm::Optional<tooling::CompileCommand> C = CDB.getCompileCommand(File);
  if (!C) // FIXME: Suppress diagnostics? Let the user know?
    C = CDB.getFallbackCommand(File);

  // Inject the resource dir.
  // FIXME: Don't overwrite it if it's already there.
  C->CommandLine.push_back("-resource-dir=" + ResourceDir);
  return std::move(*C);
}

void ClangdServer::onFileEvent(const DidChangeWatchedFilesParams &Params) {
  assert(Indexer);
  for (const FileEvent &FE : Params.changes) {
    llvm::errs() << llvm::format(" File event, path: %s, type: %d\n", FE.uri.file().str().c_str(), FE.type);
    ClangdIndexer::FileChangeType Type;
    switch (FE.type) {
     case FileChangeType::Created:
       Type = ClangdIndexer::FileChangeType::Created;
       break;
     case FileChangeType::Changed:
       Type = ClangdIndexer::FileChangeType::Changed;
       break;
     case FileChangeType::Deleted:
       Type = ClangdIndexer::FileChangeType::Deleted;
       break;
    }
    std::lock_guard<std::recursive_mutex> Lock(IndexMutex);
    Indexer->onFileEvent( { FE.uri.file(), Type });
  }
}

SymbolKind indexSymbolKindToSymbolKind(index::SymbolKind Kind) {

  switch (Kind) {
  case index::SymbolKind::Unknown:
    return SymbolKind::Variable;
  case index::SymbolKind::Module:
    return SymbolKind::Module;
  case index::SymbolKind::Namespace:
    return SymbolKind::Namespace;
  case index::SymbolKind::NamespaceAlias:
    return SymbolKind::Namespace;
  case index::SymbolKind::Macro:
    // FIXME: Need proper kind for this. See
    // https://github.com/Microsoft/language-server-protocol/issues/344
    // https://github.com/Microsoft/language-server-protocol/issues/352
    return SymbolKind::String;
  case index::SymbolKind::Enum:
    return SymbolKind::Enum;
  case index::SymbolKind::Struct:
    //FIXME: Not in released protocol. return SymbolKind::Struct;
    return SymbolKind::Class;
  case index::SymbolKind::Class:
    return SymbolKind::Class;
  case index::SymbolKind::Protocol:
    // FIXME: Need proper kind for this.
    return SymbolKind::Interface;
  case index::SymbolKind::Extension:
    // FIXME: Need proper kind for this.
    return SymbolKind::Interface;
  case index::SymbolKind::Union:
    // FIXME: Need proper kind for this.
    return SymbolKind::Class;
  case index::SymbolKind::TypeAlias:
    // FIXME: Need proper kind for this.
    return SymbolKind::Class;
  case index::SymbolKind::Function:
    return SymbolKind::Function;
  case index::SymbolKind::Variable:
    return SymbolKind::Variable;
  case index::SymbolKind::Field:
      return SymbolKind::Field;
  case index::SymbolKind::EnumConstant:
      return SymbolKind::Enum;
      //FIXME: Not in released protocol return SymbolKind::EnumMember;
  case index::SymbolKind::InstanceMethod:
  case index::SymbolKind::ClassMethod:
  case index::SymbolKind::StaticMethod:
      return SymbolKind::Method;
  case index::SymbolKind::InstanceProperty:
  case index::SymbolKind::ClassProperty:
  case index::SymbolKind::StaticProperty:
      return SymbolKind::Property;
  case index::SymbolKind::Constructor:
  case index::SymbolKind::Destructor:
      return SymbolKind::Method;
  case index::SymbolKind::ConversionFunction:
      return SymbolKind::Function;
  case index::SymbolKind::Parameter:
      return SymbolKind::Variable;
  case index::SymbolKind::Using:
      // Not sure this is correct.
      return SymbolKind::Namespace;
  }
  llvm_unreachable("invalid symbol kind");
}

//FIXME: Remove, duplicated from XRefs.cpp
llvm::Optional<Location> getLocation(SourceManager& SourceMgr, const std::string & File, uint32_t LocStart,
    uint32_t LocEnd) {
  const FileEntry *FE = SourceMgr.getFileManager().getFile(File);
  if (!FE) {
    return llvm::None;
  }
  FileID FID = SourceMgr.getOrCreateFileID(FE, SrcMgr::C_User);

  Position Begin;
  bool Invalid;
  Begin.line = SourceMgr.getLineNumber(FID, LocStart, &Invalid) - 1;
  Begin.character = SourceMgr.getColumnNumber(FID, LocStart, &Invalid) - 1;
  Position End;
  End.line = SourceMgr.getLineNumber(FID, LocEnd, &Invalid) - 1;
  End.character = SourceMgr.getColumnNumber(FID, LocEnd, &Invalid) - 1;
  Range R = { Begin, End };
  Location L;
  L.uri = URIForFile(File);
  L.range = R;
  return L;
}

llvm::Expected<std::vector<SymbolInformation>>
ClangdServer::onWorkspaceSymbol(StringRef Query) {
  std::vector<SymbolInformation> Result;
  if (Query.empty())
    return Result;

  FileSystemOptions FileOpts;
  FileManager FM(FileOpts);
  IntrusiveRefCntPtr<DiagnosticsEngine> DE(CompilerInstance::createDiagnostics(new DiagnosticOptions));
  SourceManager TempSM(*DE, FM);

  const unsigned int MAX_WORKSPACE_SYMBOLS = 1000;
  unsigned NumSymbols = 0;
  IndexDataProvider->foreachSymbols(Query, [&NumSymbols, &Result, &TempSM](ClangdIndexDataSymbol &Sym) {
    USR Usr(Sym.getUsr());
    Sym.foreachOccurrence(static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition), [&NumSymbols, &Result, &TempSM, &Sym](ClangdIndexDataOccurrence &Occurrence) {
      auto L = getLocation(TempSM, Occurrence.getPath(), Occurrence.getStartOffset(TempSM), Occurrence.getEndOffset(TempSM));
      if (L) {
        Result.push_back({Sym.getName(), indexSymbolKindToSymbolKind(Sym.getKind()), *L, Sym.getQualifier()});
        NumSymbols++;
        if (NumSymbols >= MAX_WORKSPACE_SYMBOLS)
          return false;
      }
      return true;
    });
    if (NumSymbols >= MAX_WORKSPACE_SYMBOLS)
      return false;
    return true;
  });

  llvm::errs() << llvm::format("Found %u symbols.\n", Result.size());
  return Result;
}

void ClangdServer::findReferences(
    PathRef File, Position Pos, bool IncludeDeclaration,
    Callback<std::vector<Location>> CB) {
  auto FS = FSProvider.getFileSystem();
  auto Action = [this, Pos, FS, IncludeDeclaration](Callback<std::vector<Location>> CB,
                          llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    std::vector<Location> Result;
    {
      std::lock_guard<std::recursive_mutex> Lock(IndexMutex);
      auto IndexTotalTimer = llvm::Timer("index time", "Find References Time");
      IndexTotalTimer.startTimer();
      Result = clangd::findReferences(InpAST->AST, Pos, IncludeDeclaration, IndexDataProvider);
      IndexTotalTimer.stopTimer();
      llvm::errs() << llvm::format("Found %u references.\n", Result.size());
    }
    CB(Result);
  };

  WorkScheduler.runWithAST("Definitions", File, Bind(Action, std::move(CB)));
}

void ClangdServer::codeLens(
    PathRef File,
    Callback<std::vector<CodeLens>> CB) {
  auto FS = FSProvider.getFileSystem();
  auto Action = [this, FS](Callback<std::vector<CodeLens>> CB,
                          llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    std::vector<CodeLens> Result = clangd::codeLens(InpAST->AST, IndexDataProvider);
    CB(Result);
  };

  WorkScheduler.runWithAST("CodeLens", File, Bind(Action, std::move(CB)));
}

void ClangdServer::codeLensResolve(
    const CodeLens &CL,
    Callback<CodeLens> CB) {
  auto FS = FSProvider.getFileSystem();
  auto Action = [this, CL, FS](Callback<CodeLens> CB,
                          llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    CodeLens Result = clangd::codeLensResolve(InpAST->AST, CL, IndexDataProvider);
    CB(Result);
  };

  WorkScheduler.runWithAST("CodeLensResolve", CL.data.loc.uri.file(), Bind(Action, std::move(CB)));
}

void ClangdServer::reindex() {
  if (!RootPath)
    return;

  assert(Indexer);
  std::lock_guard<std::recursive_mutex> Lock(IndexMutex);
  Indexer->reindex();
}

void ClangdServer::dumpIncludedBy(URIForFile File) {
  std::lock_guard<std::recursive_mutex> Lock(IndexMutex);
  assert(Indexer);
  IndexDataProvider->dumpIncludedBy(File.file());
}

void ClangdServer::dumpInclusions(URIForFile File) {
  std::lock_guard<std::recursive_mutex> Lock(IndexMutex);
  assert(Indexer);
  IndexDataProvider->dumpInclusions(File.file());
}

void ClangdServer::workspaceSymbols(
    StringRef Query, int Limit, Callback<std::vector<SymbolInformation>> CB) {

  if (IndexDataProvider) {
    std::vector<SymbolInformation> Result;
    if (Query.empty())
      return CB(Result);

    FileSystemOptions FileOpts;
    FileManager FM(FileOpts);
    IntrusiveRefCntPtr<DiagnosticsEngine> DE(CompilerInstance::createDiagnostics(new DiagnosticOptions));
    SourceManager TempSM(*DE, FM);

    int NumSymbols = 0;
    IndexDataProvider->foreachSymbols(Query, [&NumSymbols, Limit, &Result, &TempSM](ClangdIndexDataSymbol &Sym) {
      USR Usr(Sym.getUsr());
      Sym.foreachOccurrence(static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition), [&NumSymbols, Limit, &Result, &TempSM, &Sym](ClangdIndexDataOccurrence &Occurrence) {
        auto L = getLocation(TempSM, Occurrence.getPath(), Occurrence.getStartOffset(TempSM), Occurrence.getEndOffset(TempSM));
        if (L) {
          Result.push_back({Sym.getName(), indexSymbolKindToSymbolKind(Sym.getKind()), *L, Sym.getQualifier()});
          NumSymbols++;
          if (NumSymbols >= Limit)
            return false;
        }
        return true;
      });
      if (NumSymbols >= Limit)
        return false;
      return true;
    });

    llvm::errs() << llvm::format("Found %u symbols.\n", Result.size());
    CB(Result);
    return;
  }

  CB(clangd::getWorkspaceSymbols(Query, Limit, Index,
                                 RootPath ? *RootPath : ""));
}

void ClangdServer::documentSymbols(
    StringRef File, Callback<std::vector<SymbolInformation>> CB) {
  auto Action = [](Callback<std::vector<SymbolInformation>> CB,
                   llvm::Expected<InputsAndAST> InpAST) {
    if (!InpAST)
      return CB(InpAST.takeError());
    CB(clangd::getDocumentSymbols(InpAST->AST));
  };
  WorkScheduler.runWithAST("documentSymbols", File,
                           Bind(Action, std::move(CB)));
}

std::vector<std::pair<Path, std::size_t>>
ClangdServer::getUsedBytesPerFile() const {
  return WorkScheduler.getUsedBytesPerFile();
}

LLVM_NODISCARD bool
ClangdServer::blockUntilIdleForTest(llvm::Optional<double> TimeoutSeconds) {
  return WorkScheduler.blockUntilIdle(timeoutSeconds(TimeoutSeconds));
}

void ClangdServer::printStats() {
  if (!RootPath)
    return;

  assert(Indexer);
  std::lock_guard<std::recursive_mutex> Lock(IndexMutex);
  Indexer->printStats();
}
