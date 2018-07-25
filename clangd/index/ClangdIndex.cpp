#include "ClangdIndex.h"
#include "ClangdIndexString.h"

#include <unordered_map>

namespace clang {
namespace clangd {

ClangdIndexSymbol::ClangdIndexSymbol(ClangdIndexDataStorage &Storage, USR Usr,
    std::string Name, std::string Qualifier, index::SymbolKind Kind,
    ClangdIndex& Index) :
    Index(Index), Storage(Index.getStorage()) {
  Record = Storage.mallocRecord(RECORD_SIZE);
  Storage.putRecPtr(Record + USR_OFFSET,
      ClangdIndexString(Storage, Usr.c_str()).getRecord());
  Storage.putRecPtr(Record + NAME_OFFSET,
      ClangdIndexString(Storage, Name.c_str()).getRecord());
  Storage.putInt8(Record + KIND_OFFSET, static_cast<uint8_t>(Kind));
  static_assert(sizeof(uint8_t) == sizeof(index::SymbolKind), "SymbolKind cannot fit in uint8_t");

  Storage.putRecPtr(Record + QUALIFIER_OFFSET,
      ClangdIndexString(Storage, Qualifier.c_str()).getRecord());
  assert(!getFirstOccurrence());
}

ClangdIndexSymbol::ClangdIndexSymbol(ClangdIndexDataStorage &Storage, RecordPointer Record, ClangdIndex &Index) :
    Record(Record), Index(Index), Storage(Index.getStorage()) {
  assert (Record >= ClangdIndexDataStorage::DATA_AREA);
}

std::string ClangdIndexSymbol::getUsr() {
  return ClangdIndexString(Storage, Storage.getRecPtr(Record + USR_OFFSET)).getString();
}

std::string ClangdIndexSymbol::getName() {
  return ClangdIndexString(Storage, Storage.getRecPtr(Record + NAME_OFFSET)).getString();
}

index::SymbolKind ClangdIndexSymbol::getKind() {
  return static_cast<index::SymbolKind>(Storage.getInt8(Record + KIND_OFFSET));
}

std::string ClangdIndexSymbol::getQualifier() {
  return ClangdIndexString(Storage, Storage.getRecPtr(Record + QUALIFIER_OFFSET)).getString();
}

void ClangdIndexSymbol::foreachOccurrence(llvm::Optional<index::SymbolRoleSet> RolesFilter, llvm::function_ref<bool(ClangdIndexOccurrence&)> Receiver) {
  auto Occurrence = getFirstOccurrence();
  while (Occurrence) {
    auto NextOccurence = Occurrence->getNextOccurrence();
    if (!RolesFilter || (Occurrence->getRoles() & *RolesFilter)) {
      if (!Receiver(*Occurrence))
        break;
    }
    Occurrence = std::move(NextOccurence);
  }
}

std::unique_ptr<ClangdIndexOccurrence> loadIndexOccurrence(ClangdIndexDataStorage &Storage, RecordPointer Offset, ClangdIndex &Index) {
  RecordPointer Rec = Storage.getRecPtr(Offset);
  if (Rec == 0)
    return {};
  ClangdIndexOccurrence::ClangdIndexOccurrenceType Type;
  Storage.getData(Rec, &Type, sizeof(ClangdIndexOccurrence::ClangdIndexOccurrenceType));
  switch (Type) {
  case ClangdIndexOccurrence::ClangdIndexOccurrenceType::OCCURRENCE:
    return llvm::make_unique<ClangdIndexOccurrence>(Storage, Rec, Index);
  case ClangdIndexOccurrence::ClangdIndexOccurrenceType::DEFINITION_OCCURRENCE:
    return llvm::make_unique<ClangdIndexDefinitionOccurrence>(Storage, Rec, Index);
  }
  llvm_unreachable("Invalid IndexOccurrence type. Index corrupted?");
}

std::unique_ptr<ClangdIndexOccurrence> ClangdIndexSymbol::getFirstOccurrence() {
  return loadIndexOccurrence(Storage, Record + FIRST_OCCURRENCE, Index);
}

void ClangdIndexSymbol::setFirstOccurrence(ClangdIndexOccurrence &Occurrence) {
  Storage.putRecPtr(Record + FIRST_OCCURRENCE, Occurrence.getRecord());
}

void ClangdIndexSymbol::clearFirstOccurrence() {
  Storage.putRecPtr(Record + FIRST_OCCURRENCE, 0);
}

void ClangdIndexSymbol::addOccurrence(ClangdIndexOccurrence &Occurrence) {
  auto FirstOccurrence = getFirstOccurrence();
  setFirstOccurrence(Occurrence);
  if (FirstOccurrence) {
    Occurrence.setNextOccurrence(*FirstOccurrence);
  }
}

void ClangdIndexSymbol::removeOccurrences(std::set<RecordPointer> ToBeRemoved) {
  std::unique_ptr<ClangdIndexOccurrence> Prev;
  auto Occurrence = getFirstOccurrence();
  while (Occurrence) {
    auto NextOccurrence = Occurrence->getNextOccurrence();
    RecordPointer CurRec = Occurrence->getRecord();
    if (ToBeRemoved.find(CurRec) != ToBeRemoved.end()) {
      // We have to delete something!
      assert(getRecord() == Occurrence->getSymbol()->getRecord());
      // Handle when it is the first one. Find a new first if any.
      if (getFirstOccurrence()->getRecord() == CurRec) {
        if (NextOccurrence) {
          setFirstOccurrence(*NextOccurrence);
        } else {
          clearFirstOccurrence();
        }
      } else {
        assert(Prev);
        if (NextOccurrence) {
          Prev->setNextOccurrence(*NextOccurrence);
        } else {
          Prev->clearNextOccurrence();
        }
      }

      Occurrence->free();
    } else {
      Prev = std::move(Occurrence);
    }
    Occurrence = std::move(NextOccurrence);
  }

  if (!getFirstOccurrence()) {
    // No more occurrences? No reason to live anymore.
    free();
  }
}

void ClangdIndexSymbol::free() {
  assert(!Index.getSymbols(USR(getUsr())).empty());
  // FIXME: We should assert here, not in debug.
  Index.getSymbolBTree().remove(getRecord());
  Index.getSymbolNameBTree().remove(getRecord());
  // Free the string we allocated ourselves
  Storage.freeRecord(Storage.getRecPtr(Record + USR_OFFSET));
  Storage.freeRecord(Storage.getRecPtr(Record + NAME_OFFSET));
  Storage.freeRecord(Storage.getRecPtr(Record + QUALIFIER_OFFSET));
  Storage.freeRecord(Record);
}

ClangdIndexOccurrence::ClangdIndexOccurrence(ClangdIndexDataStorage &Storage, ClangdIndex& Index, const ClangdIndexFile& File, ClangdIndexSymbol &Symbol,
    IndexSourceLocation LocStart, IndexSourceLocation LocEnd, index::SymbolRoleSet Roles) :
        ClangdIndexOccurrence(Storage, Index, File, Symbol,
 LocStart, LocEnd, Roles, RECORD_SIZE) {
}

ClangdIndexOccurrence::ClangdIndexOccurrence(ClangdIndexDataStorage &Storage, ClangdIndex& Index, const ClangdIndexFile& File, ClangdIndexSymbol &Symbol,
    IndexSourceLocation LocStart, IndexSourceLocation LocEnd, index::SymbolRoleSet Roles, unsigned RecordSize) : Index(Index), Storage(Index.getStorage()) {
  Record = Storage.mallocRecord(RecordSize);
  setOccurrenceType(ClangdIndexOccurrenceType::OCCURRENCE);
  Storage.putRecPtr(Record + SYMBOL_OFFSET, Symbol.getRecord());
  Storage.putRecPtr(Record + FILE_OFFSET, File.getRecord());
  Storage.putInt32(Record + LOC_START_OFFSET, LocStart);
  Storage.putInt32(Record + LOC_END_OFFSET, LocEnd);
  static_assert(index::SymbolRoleBitNum <= sizeof(uint32_t) * 8, "SymbolRoles cannot fit in uint32_t");
  Storage.putInt32(Record + ROLES_OFFSET, static_cast<uint32_t>(Roles));
}

ClangdIndexOccurrence::ClangdIndexOccurrence(ClangdIndexDataStorage &Storage, RecordPointer Record, ClangdIndex &Index) :
    Record(Record), Index(Index), Storage(Index.getStorage()) {
  assert (Record >= ClangdIndexDataStorage::DATA_AREA);
  loadOccurrenceType();
}

std::unique_ptr<ClangdIndexSymbol> ClangdIndexOccurrence::getSymbol() {
  return getPtrOrNull<ClangdIndexSymbol>(Storage, Record + SYMBOL_OFFSET, Index);
}

std::string ClangdIndexOccurrence::getPath() {
  RecordPointer Rec = Storage.getRecPtr(Record + FILE_OFFSET);
  if (Rec == 0) {
    return {};
  }
  return ClangdIndexFile(Storage, Rec, Index).getPath();
}

std::unique_ptr<ClangdIndexOccurrence> ClangdIndexOccurrence::getNextInFile() {
  return loadIndexOccurrence(Storage, Record + FILE_NEXT_OFFSET, Index);
}

void ClangdIndexOccurrence::setNextInFile (ClangdIndexOccurrence &Occurrence) {
  Storage.putRecPtr(Record + FILE_NEXT_OFFSET, Occurrence.getRecord());
}

std::unique_ptr<ClangdIndexOccurrence> ClangdIndexOccurrence::getNextOccurrence() {
  return loadIndexOccurrence(Storage, Record + SYMBOL_NEXT_OCCURENCE, Index);
}

void ClangdIndexOccurrence::setNextOccurrence(ClangdIndexOccurrence &Occurrence) {
  Storage.putRecPtr(Record + SYMBOL_NEXT_OCCURENCE, Occurrence.getRecord());
}

void ClangdIndexOccurrence::clearNextOccurrence() {
  Storage.putRecPtr(Record + SYMBOL_NEXT_OCCURENCE, 0);
}

void ClangdIndexOccurrence::free() {
  Storage.freeRecord(Record);
}

ClangdIndexHeaderInclusion::ClangdIndexHeaderInclusion(ClangdIndexDataStorage &Storage,
    const ClangdIndexFile& IncludedByFile, const ClangdIndexFile& IncludedFile,
    ClangdIndex &Index) :
    Index(Index), Storage(Storage) {
  Record = Storage.mallocRecord(RECORD_SIZE);
  Storage.putRecPtr(Record + INCLUDED_BY_FILE, IncludedByFile.getRecord());
  Storage.putRecPtr(Record + INCLUDED_FILE, IncludedFile.getRecord());
}

ClangdIndexHeaderInclusion::ClangdIndexHeaderInclusion(ClangdIndexDataStorage &Storage,
    RecordPointer Record, ClangdIndex &Index) :
    Record(Record), Index(Index), Storage(Storage) {
}

std::unique_ptr<ClangdIndexFile> ClangdIndexHeaderInclusion::getIncluded () {
  return getPtrOrNull<ClangdIndexFile>(Storage, Record + INCLUDED_FILE, Index);
}

std::unique_ptr<ClangdIndexFile> ClangdIndexHeaderInclusion::getIncludedBy () {
  return getPtrOrNull<ClangdIndexFile>(Storage, Record + INCLUDED_BY_FILE, Index);
}

std::unique_ptr<ClangdIndexHeaderInclusion> ClangdIndexHeaderInclusion::getPrevIncludeBy() {
  return getPtrOrNull<ClangdIndexHeaderInclusion>(Storage, Record + PREV_INCLUDED_BY, Index);
}

std::unique_ptr<ClangdIndexHeaderInclusion> ClangdIndexHeaderInclusion::getNextIncludeBy() {
  return getPtrOrNull<ClangdIndexHeaderInclusion>(Storage, Record + NEXT_INCLUDED_BY, Index);
}

std::unique_ptr<ClangdIndexHeaderInclusion> ClangdIndexHeaderInclusion::getPrevInclusion() {
  return getPtrOrNull<ClangdIndexHeaderInclusion>(Storage, Record + PREV_INCLUDES, Index);
}

std::unique_ptr<ClangdIndexHeaderInclusion> ClangdIndexHeaderInclusion::getNextInclusion() {
  return getPtrOrNull<ClangdIndexHeaderInclusion>(Storage, Record + NEXT_INCLUDES, Index);
}

ClangdIndexFile::ClangdIndexFile(ClangdIndexDataStorage &Storage, std::string Path, ClangdIndex &Index) :
    Path(Path), Index(Index), Storage(Storage) {
  Record = Storage.mallocRecord(RECORD_SIZE);
  ClangdIndexString Str(Storage, Path);
  Storage.putRecPtr(Record + PATH, Str.getRecord());
}

ClangdIndexFile::ClangdIndexFile(ClangdIndexDataStorage &Storage, RecordPointer Record, ClangdIndex &Index) :
    Record(Record), Index(Index), Storage(Storage) {
  assert (Record >= ClangdIndexDataStorage::DATA_AREA);
}

const std::string& ClangdIndexFile::getPath() {
  if (Path.empty()) {
    std::string Str = ClangdIndexString(Storage,
        Storage.getRecPtr(Record + PATH)).getString();
    Path = Str;
  }
  return Path;
}

std::unique_ptr<ClangdIndexOccurrence> ClangdIndexFile::getFirstOccurrence() {
  return loadIndexOccurrence(Storage, Record + FIRST_OCCURRENCE, Index);
}

std::unique_ptr<ClangdIndexHeaderInclusion> ClangdIndexFile::getFirstIncludedBy() {
  return getPtrOrNull<ClangdIndexHeaderInclusion>(Storage, Record + FIRST_INCLUDED_BY, Index);
}

std::unique_ptr<ClangdIndexHeaderInclusion> ClangdIndexFile::getFirstInclusion() {
  return getPtrOrNull<ClangdIndexHeaderInclusion>(Storage, Record + FIRST_INCLUSION, Index);
}

void ClangdIndexFile::addOccurrence(ClangdIndexOccurrence &Occurrence) {
  auto FirstOccurrence = getFirstOccurrence();
  setFirstOccurrence(Occurrence.getRecord());
  if (FirstOccurrence) {
    Occurrence.setNextInFile(*FirstOccurrence);
  }
}

void ClangdIndexFile::setLastIndexingTime(
    std::chrono::nanoseconds LastIndexingTime) {
  auto Count = LastIndexingTime.count();
  RecordPointer Rec = Storage.getRecPtr(Record + LAST_INDEXING_TIME);
  if (Rec) {
    // FIXME: We probably shouldn't realloc every time the indexing time changes.
    // Just overwrite the data.
    Storage.freeRecord(Rec);
  }
  // Note: The size of std::chrono::nanoseconds::rep might vary between systems
  Rec = Storage.mallocRecord(sizeof(std::chrono::nanoseconds::rep));
  Storage.putRecPtr(Record + LAST_INDEXING_TIME, Rec);
  Storage.putData(Rec, &Count, sizeof(std::chrono::nanoseconds::rep));
}

llvm::Optional<std::chrono::nanoseconds> ClangdIndexFile::getLastIndexingTime() {
  RecordPointer Rec = Storage.getRecPtr(Record + LAST_INDEXING_TIME);
  if (!Rec) {
    return llvm::None;
  }
  std::chrono::nanoseconds::rep Count;
  Storage.getData(Rec, &Count, sizeof(std::chrono::nanoseconds::rep));
  return std::chrono::nanoseconds(Count);
}

void ClangdIndexFile::clearIndexingTime() {
  RecordPointer Rec = Storage.getRecPtr(Record + LAST_INDEXING_TIME);
  if (Rec) {
    Storage.freeRecord(Rec);
    Storage.putRecPtr(Record + LAST_INDEXING_TIME, 0);
  }
}

void ClangdIndexFile::clearOccurrences() {
  std::unordered_map<RecordPointer, std::set<RecordPointer>> SymbolsToDeletedOccurrences;
  auto Occurrence = getFirstOccurrence();
  while (Occurrence) {
    auto NextOccurrence = Occurrence->getNextInFile();
    auto Symbol = Occurrence->getSymbol();
    if (Symbol) {
      SymbolsToDeletedOccurrences[Symbol->getRecord()].insert(Occurrence->getRecord());
    } else {
      llvm::errs() << "Warning: Deleting orphaned occurrence: " << Occurrence->getRecord() << "\n";
    }
    Occurrence = std::move(NextOccurrence);
  }
  for (auto &I : SymbolsToDeletedOccurrences) {
    ClangdIndexSymbol Sym(Storage, I.first, Index);
    auto USR1 = Sym.getUsr();
    assert(!USR1.empty());
  }
  for (auto &I : SymbolsToDeletedOccurrences) {
    ClangdIndexSymbol Sym(Storage, I.first, Index);
    Sym.removeOccurrences(I.second);
  }

  setFirstOccurrence(0);
}

void ClangdIndexFile::clearInclusions() {
  auto Inclusion = getFirstInclusion();
  while (Inclusion) {
    auto NextInclusion = Inclusion->getNextInclusion();
    auto Prev = Inclusion->getPrevIncludeBy();
    auto Next = Inclusion->getNextIncludeBy();
    RecordPointer NextRec = Next ? Next->getRecord() : 0;
    if (Prev) {
      Prev->setNextIncludedBy(NextRec);
      if (Next) {
        Next->setPrevIncludedBy(Prev->getRecord());
      }
    } else {
      Inclusion->getIncluded()->setFirstIncludedBy(NextRec);
      if (Next) {
        Next->setPrevIncludedBy(0);
      }
    }
    Inclusion->free();
    Inclusion = std::move(NextInclusion);
  }
  setFirstInclusion(0);
}

void ClangdIndexFile::clearIncludedBys() {
  auto IncludedBy = getFirstIncludedBy();
  while (IncludedBy) {
    auto NextIncludedBy = IncludedBy->getNextIncludeBy();
    auto Prev = IncludedBy->getPrevInclusion();
    auto Next = IncludedBy->getNextInclusion();
    RecordPointer NextRec = Next ? Next->getRecord() : 0;
    if (Prev) {
      Prev->setNextInclusion(NextRec);
      if (Next) {
        Next->setPrevInclusion(Prev->getRecord());
      }
    } else {
      IncludedBy->getIncludedBy()->setFirstInclusion(NextRec);
      if (Next) {
        Next->setPrevInclusion(0);
      }
    }
    IncludedBy->free();
    IncludedBy = std::move(NextIncludedBy);
  }
  setFirstIncludedBy(0);
}

void ClangdIndexFile::visitDependentFiles(DependentVisitor &Visitor,
    ClangdIndexFile &File, std::set<RecordPointer> &VisitedFiles) {
  auto IncludedBy = File.getFirstIncludedBy();
  if (!IncludedBy) {
    return;
  }

  for (;IncludedBy; IncludedBy = IncludedBy->getNextIncludeBy()) {
    auto IncludedByFile = IncludedBy->getIncludedBy();
    assert(IncludedByFile && "inclusion pointing to non-existent file");

    if (VisitedFiles.find(IncludedByFile->getRecord()) != VisitedFiles.end()) {
      continue;
    }
    VisitedFiles.insert(IncludedByFile->getRecord());

    auto Res = Visitor.VisitDependent(*IncludedByFile);
    if (Res == NodeVisitResult::ABORT)
      break;
    else if (Res == NodeVisitResult::SKIP) {
      continue;
    }

    Visitor.EnterFile(*IncludedByFile);
    visitDependentFiles(Visitor, *IncludedByFile, VisitedFiles);
    Visitor.LeaveFile(*IncludedByFile);
  }
}

void ClangdIndexFile::visitDependentFiles(DependentVisitor &Visitor) {
  // Prevent infinite recursion with this set.
  std::set<RecordPointer> VisitedFiles;
  visitDependentFiles(Visitor, *this, VisitedFiles);
}

void ClangdIndexFile::visitInclusions(InclusionVisitor &Visitor,
    ClangdIndexFile &File, std::set<RecordPointer> &VisitedFiles) {
  auto Inclusion = File.getFirstInclusion();
  if (!Inclusion) {
    return;
  }

  for (; Inclusion; Inclusion = Inclusion->getNextInclusion()) {
    auto IncludedFile = Inclusion->getIncluded();
    assert(IncludedFile && "inclusion pointing to non-existent file");

    if (VisitedFiles.find(IncludedFile->getRecord()) != VisitedFiles.end()) {
      continue;
    }
    VisitedFiles.insert(IncludedFile->getRecord());

    auto Res = Visitor.VisitInclusion(*IncludedFile);
    if (Res == NodeVisitResult::ABORT)
      break;
    else if (Res == NodeVisitResult::SKIP) {
      continue;
    }

    Visitor.EnterFile(*IncludedFile);
    visitInclusions(Visitor, *IncludedFile, VisitedFiles);
    Visitor.LeaveFile(*IncludedFile);
  }
}

void ClangdIndexFile::visitInclusions(InclusionVisitor &Visitor) {
  //Prevent infinite recursion with this set.
  std::set<RecordPointer> VisitedFiles;
  Visitor.EnterFile(*this);
  visitInclusions(Visitor, *this, VisitedFiles);
  Visitor.LeaveFile(*this);
}

void ClangdIndexFile::onChange() {
  clearIndexingTime();
  clearOccurrences();
  clearInclusions();
  // Don't clear includedBys, those relation ships depend on the content of
  // other files, not this one. If we removed them, we would have to re-index
  // all the included-by files.
}

void ClangdIndexFile::free() {
  clearOccurrences();
  clearInclusions();
  clearIncludedBys();

  assert(Index.getFilesBTree().remove(getRecord()));
  Storage.freeRecord(Storage.getRecPtr(Record + PATH));
  Storage.freeRecord(Record);
}

namespace {
class SymbolUSRVisitor: public BTreeVisitor {
  USR Usr;
  ClangdIndex &Index;
  llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> Result;

public:
  SymbolUSRVisitor(USR Usr, ClangdIndex &Index) :
      Usr(Usr), Index(Index) {
  }

  int compare(RecordPointer Record) override {
    ClangdIndexSymbol Current(Index.getStorage(), Record, Index);
    std::string CurrentUsr = Current.getUsr();
    return CurrentUsr.compare(Usr.c_str());
  }

  void visit(RecordPointer Record) override {
    std::unique_ptr<ClangdIndexSymbol> Current = llvm::make_unique<
        ClangdIndexSymbol>(Index.getStorage(), Record, Index);
    Result.push_back(std::move(Current));
  }

  llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> getResult() {
    return std::move(Result);
  }
};
}

void ClangdIndex::addSymbol(ClangdIndexSymbol &Symbol) {
  SymbolBTree.insert(Symbol.getRecord());
  SymbolNameBTree.insert(Symbol.getRecord());
}

llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> ClangdIndex::getSymbols(
    const USR& Buf) {
  SymbolUSRVisitor Visitor(Buf, *this);
  SymbolBTree.accept(Visitor);
  return Visitor.getResult();
}

llvm::SmallVector<std::unique_ptr<ClangdIndexOccurrence>, 1> ClangdIndex::getDefinitions(
      const USR& Buf) {
  return getOccurrences(Buf, static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
}

llvm::SmallVector<std::unique_ptr<ClangdIndexOccurrence>, 1> ClangdIndex::getReferences(
      const USR& Buf) {
  return getOccurrences(Buf,
      static_cast<index::SymbolRoleSet>(index::SymbolRole::Reference)
          | static_cast<index::SymbolRoleSet>(index::SymbolRole::Declaration)
          | static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
}

llvm::SmallVector<std::unique_ptr<ClangdIndexOccurrence>, 1> ClangdIndex::getOccurrences(const USR& Buf, index::SymbolRoleSet Roles) {
  auto Symbols = getSymbols(Buf);
  if (Symbols.empty()) {
    return {};
  }

  //FIXME: multiple symbols?
  auto Symbol = *Symbols.front();
  llvm::SmallVector<std::unique_ptr<ClangdIndexOccurrence>, 1> Result;
  auto Occurrence = Symbol.getFirstOccurrence();
  while (Occurrence) {
    auto NextOccurence = Occurrence->getNextOccurrence();
    if (Occurrence->getRoles() & Roles) {
      Result.push_back(std::move(Occurrence));
    }
    Occurrence = std::move(NextOccurence);
  }

  return Result;
}

namespace {
class FileVisitor: public BTreeVisitor {

  std::string FilePath;
  ClangdIndex &Index;
  std::unique_ptr<ClangdIndexFile> Result;

public:
  FileVisitor(std::string FilePath, ClangdIndex &Index) :
      FilePath(FilePath), Index(Index) {
  }

  int compare(RecordPointer Record) override {
    ClangdIndexFile Current(Index.getStorage(), Record, Index);
    return Current.getPath().compare(FilePath);
  }

  void visit(RecordPointer Record) override {
    std::unique_ptr<ClangdIndexFile> Current = llvm::make_unique<
        ClangdIndexFile>(Index.getStorage(), Record, Index);
    Result = std::move(Current);
  }

  std::unique_ptr<ClangdIndexFile> getResult() {
    return std::move(Result);
  }
};
}

ClangdIndex::ClangdIndex(std::string File) : File(File),
    Storage(File, VERSION), SymbolsUSRComparator(*this),
    SymbolsNameComparator(*this),
    SymbolBTree(Storage,
        SYMBOLS_TREE_OFFSET, SymbolsUSRComparator),
        SymbolNameBTree(Storage,
                SYMBOLS_NAME_TREE_OFFSET, SymbolsNameComparator),
        FilesComparator(*this), FilesBTree(
        Storage, FILES_TREE_OFFSET, FilesComparator) {
}

std::unique_ptr<ClangdIndexFile> ClangdIndex::getFile(
    const std::string& FilePath) {
  assert(!FilePath.empty());
  FileVisitor FV(FilePath, *this);
  FilesBTree.accept(FV);
  return FV.getResult();
}

void ClangdIndex::dumpSymbolsTree() {
  getSymbolBTree().dump([this](RecordPointer Rec, llvm::raw_ostream &OS) {
      OS << ClangdIndexSymbol(Storage, Rec, *this).getUsr();
    }, llvm::errs());
}

namespace {
class SymbolNameVisitor: public BTreeVisitor {
  std::string SymbolName;
  ClangdIndex &Index;
  llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> Result;

public:
  SymbolNameVisitor(std::string SymbolName, ClangdIndex &Index) :
    SymbolName(SymbolName), Index(Index) {
  }

  int compare(RecordPointer Record) override {
    ClangdIndexSymbol Current(Index.getStorage(), Record, Index);
    std::string CurrentName = Current.getName();
    if (CurrentName.rfind(SymbolName, 0) == 0) {
      return 0;
    }

    return CurrentName.compare(SymbolName.c_str());
  }

  void visit(RecordPointer Record) override {
    std::unique_ptr<ClangdIndexSymbol> Current = llvm::make_unique<
        ClangdIndexSymbol>(Index.getStorage(), Record, Index);
    Result.push_back(std::move(Current));
  }

  llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> getResult() {
    return std::move(Result);
  }
};
}

//FIXME: This can only query using a non-qualified name.
void ClangdIndex::foreachSymbols(StringRef Query,
    llvm::function_ref<bool(ClangdIndexSymbol&)> Receiver) {
  SymbolNameVisitor Visitor(Query, *this);
  SymbolNameBTree.accept(Visitor);
  auto Syms = Visitor.getResult();
  for (auto &Sym : Syms) {
    if (!Receiver(*Sym))
      break;
  }
}

void ClangdIndex::foreachSymbols(const USR &Usr,
    llvm::function_ref<bool(ClangdIndexSymbol&)> Receiver) {
  SymbolUSRVisitor Visitor(Usr, *this);
  SymbolBTree.accept(Visitor);
  auto Syms = Visitor.getResult();
  for (auto &Sym : Syms) {
    if (!Receiver(*Sym))
      break;
  }
}

void ClangdIndex::foreachSymbols(llvm::function_ref<bool(ClangdIndexSymbol&)> Receiver) {
  class SymbolAllVisitor: public BTreeVisitor {
    ClangdIndex &Index;
    llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> Result;

  public:
    SymbolAllVisitor(ClangdIndex &Index) :
        Index(Index) {
    }

    int compare(RecordPointer Record) override {
      return 0;
    }

    void visit(RecordPointer Record) override {
      std::unique_ptr<ClangdIndexSymbol> Current = llvm::make_unique<
          ClangdIndexSymbol>(Index.getStorage(), Record, Index);
      Result.push_back(std::move(Current));
    }

    llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> getResult() {
      return std::move(Result);
    }
  };
  SymbolAllVisitor Visitor(*this);
  SymbolBTree.accept(Visitor);
  auto Syms = Visitor.getResult();
  for (auto &Sym : Syms) {
    Receiver(*Sym);
  }
}

void ClangdIndex::dumpFilesTree() {
  getFilesBTree().dump([this](RecordPointer Rec, llvm::raw_ostream &OS) {
      OS << ClangdIndexFile(Storage, Rec, *this).getPath();
    }, llvm::errs());
}

} // namespace clangd
} // namespace clang
