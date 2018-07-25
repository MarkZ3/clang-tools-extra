#ifndef TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_INDEXSTORE_CLANGDINDEXSTOREDATABUILDER_H_
#define TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_INDEXSTORE_CLANGDINDEXSTOREDATABUILDER_H_

#include "../ClangdIndexer.h"
#include "../ClangdIndexDataProvider.h"

#include "../BTree.h"
#include "../ClangdIndexDataStorage.h"
#include "../ClangdIndexString.h"

#include "indexstore/IndexStoreCXX.h"

#include <set>

namespace clang {
namespace clangd {

class GlobalCompilationDatabase;

class ClangdIndexStoreIndexer : public ClangdIndexer, public ClangdIndexDataProvider {
  bool DebugSymbol = false;
  std::string RootPath;
  GlobalCompilationDatabase &CDB;

  std::unique_ptr<indexstore::IndexStore> DataStore;

  /// Mapping data
public:
  class IndexStoreSymbolRelevanceInfo {
    ClangdIndexDataStorage &DataStorage;
    RecordPointer Rec;

    std::string UnitName;

    const static OffsetInRecord NEXT_SYMBOL_RELEVANCE_INFO_OFFSET = 0;
    const static OffsetInRecord RECORD_PTR_OFFSET = NEXT_SYMBOL_RELEVANCE_INFO_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
    const static OffsetInRecord ROLES_OFFSET = RECORD_PTR_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
    const static OffsetInRecord RECORD_SIZE = ROLES_OFFSET + ClangdIndexDataStorage::INT32_SIZE;

  public:
    IndexStoreSymbolRelevanceInfo(ClangdIndexDataStorage &DataStorage, RecordPointer RecordFile, index::SymbolRoleSet Roles) : DataStorage(DataStorage) {
      Rec = DataStorage.mallocRecord(RECORD_SIZE);
      DataStorage.putRecPtr(Rec + RECORD_PTR_OFFSET, RecordFile);
      static_assert(index::SymbolRoleBitNum <= sizeof(uint32_t) * 8, "SymbolRoles cannot fit in uint32_t");
      DataStorage.putInt32(Rec + ROLES_OFFSET, static_cast<uint32_t>(Roles));
      assert(!getNextSymbolRelevanceInfo());
    }

    IndexStoreSymbolRelevanceInfo(ClangdIndexDataStorage &DataStorage, RecordPointer Rec) : DataStorage(DataStorage), Rec(Rec) {
    }

    std::string getRecordName() {
      return IndexStoreRecord(DataStorage, DataStorage.getRecPtr(Rec + RECORD_PTR_OFFSET)).getName();
    }

    index::SymbolRoleSet getRoles() {
      return static_cast<index::SymbolRoleSet>(DataStorage.getInt32(
          Rec + ROLES_OFFSET));
    }

    RecordPointer getRecord() {
      return Rec;
    }

    std::unique_ptr<IndexStoreSymbolRelevanceInfo> getNextSymbolRelevanceInfo() {
      return getPtrOrNull<IndexStoreSymbolRelevanceInfo>(DataStorage, Rec + NEXT_SYMBOL_RELEVANCE_INFO_OFFSET);
    }

    void setNextSymbolRelevanceInfo(IndexStoreSymbolRelevanceInfo &Occurrence) {
      DataStorage.putRecPtr(Rec + NEXT_SYMBOL_RELEVANCE_INFO_OFFSET, Occurrence.getRecord());
    }
  };

  class IndexStoreSymbol {
    ClangdIndexDataStorage &MappingsDataStorage;
    indexstore::IndexStore &DataStore;
    RecordPointer Record;

    // Caches
    bool Loaded = false;
    std::string Name;
    index::SymbolKind Kind = index::SymbolKind::Unknown;
    std::string Usr;

    const static OffsetInRecord USR_OFFSET = 0;
    const static OffsetInRecord NAME_OFFSET = USR_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
    const static OffsetInRecord RECORD_FILE_OFFSET = NAME_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
    const static OffsetInRecord FIRST_SYMBOL_RELEVANCE_INFO_OFFSET = RECORD_FILE_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
    const static OffsetInRecord RECORD_SIZE  = FIRST_SYMBOL_RELEVANCE_INFO_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
  public:
    IndexStoreSymbol(ClangdIndexDataStorage &MappingsDataStorage, indexstore::IndexStore &DataStore, std::string Usr, std::string Name, RecordPointer RecordFile) : MappingsDataStorage(MappingsDataStorage), DataStore(DataStore) {
      Record = MappingsDataStorage.mallocRecord(RECORD_SIZE);
      MappingsDataStorage.putRecPtr(Record + USR_OFFSET, ClangdIndexString(MappingsDataStorage, Usr).getRecord());
      MappingsDataStorage.putRecPtr(Record + NAME_OFFSET, ClangdIndexString(MappingsDataStorage, Name).getRecord());
      MappingsDataStorage.putRecPtr(Record + RECORD_FILE_OFFSET, RecordFile);
      assert(!getFirstSymbolRelevanceInfo());
    }

    RecordPointer getRecord() {
      return Record;
    }

    IndexStoreSymbol(ClangdIndexDataStorage &MappingsDataStorage, indexstore::IndexStore &DataStore, RecordPointer Rec) : MappingsDataStorage(MappingsDataStorage), DataStore(DataStore), Record(Rec) {
    }

    index::SymbolKind getKind() {
      if (!Loaded)
        loadIndexStoreInfo();
      return Kind;
    }

    std::string getUsr() {
      if (!Usr.empty())
        return Usr;
      Usr = ClangdIndexString(MappingsDataStorage, MappingsDataStorage.getRecPtr(Record + USR_OFFSET)).getString();
      return Usr;
    }

    std::string getName() {
      if (!Name.empty())
        return Name;
      Name = ClangdIndexString(MappingsDataStorage, MappingsDataStorage.getRecPtr(Record + NAME_OFFSET)).getString();
      return Name;
    }

    std::unique_ptr<IndexStoreSymbolRelevanceInfo> getFirstSymbolRelevanceInfo() {
      return getPtrOrNull<IndexStoreSymbolRelevanceInfo>(MappingsDataStorage, Record + FIRST_SYMBOL_RELEVANCE_INFO_OFFSET);
    }

    void addSymbolRelevanceInfo(IndexStoreSymbolRelevanceInfo &Info) {
      auto FirstSymbolRelevanceInfo = getFirstSymbolRelevanceInfo();
      setFirstSymbolRelevanceInfo(Info);
      if (FirstSymbolRelevanceInfo) {
        Info.setNextSymbolRelevanceInfo(*FirstSymbolRelevanceInfo);
      }
    }

  private:
    void setFirstSymbolRelevanceInfo(IndexStoreSymbolRelevanceInfo &Info) {
      MappingsDataStorage.putRecPtr(Record + FIRST_SYMBOL_RELEVANCE_INFO_OFFSET, Info.getRecord());
    }

    void loadIndexStoreInfo();
  };

  class IndexStoreRecord {
      ClangdIndexDataStorage &DataStorage;
      RecordPointer Record;

      const static OffsetInRecord RECORD_NAME_OFFSET = 0;
      const static OffsetInRecord FULL_PATH_OFFSET = RECORD_NAME_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
      const static OffsetInRecord RECORD_SIZE  = FULL_PATH_OFFSET + ClangdIndexDataStorage::PTR_SIZE;
    public:
      IndexStoreRecord(ClangdIndexDataStorage &DataStorage, std::string RecordName) : DataStorage(DataStorage) {
        Record = DataStorage.mallocRecord(RECORD_SIZE);
        ClangdIndexString Str(DataStorage, RecordName.c_str());
        DataStorage.putRecPtr(Record + RECORD_NAME_OFFSET, Str.getRecord());
      }

      IndexStoreRecord(ClangdIndexDataStorage &DataStorage, RecordPointer Rec) : DataStorage(DataStorage), Record(Rec) {
      }

      RecordPointer getRecord() {
        return Record;
      }

      std::string getName() {
        return ClangdIndexString(DataStorage, DataStorage.getRecPtr(Record + RECORD_NAME_OFFSET)).getString();
      }

      std::string getFullPath() {
        RecordPointer Rec = DataStorage.getRecPtr(Record + FULL_PATH_OFFSET);
        if (Rec == 0) {
          return {};
        }
        return ClangdIndexString(DataStorage, Rec).getString();
      }
      void setFullPath(std::string FullPath) {
        if (FullPath.empty())
          return;
        ClangdIndexString WorkingDirStr(DataStorage, FullPath.c_str());
        DataStorage.putRecPtr(Record + FULL_PATH_OFFSET, WorkingDirStr.getRecord());
      }
    };


  class IndexStoreFile;

  //TODO: We should remove this and just store dependents files in flat list
  // and only use data from the index-store to compute it.
  class IndexStoreHeaderInclusion {
    const static int INCLUDED_BY_FILE = 0;
    const static int INCLUDED_FILE = INCLUDED_BY_FILE + ClangdIndexDataStorage::PTR_SIZE;
    const static int PREV_INCLUDED_BY = INCLUDED_FILE + ClangdIndexDataStorage::PTR_SIZE;
    const static int NEXT_INCLUDED_BY = PREV_INCLUDED_BY + ClangdIndexDataStorage::PTR_SIZE;
    const static int PREV_INCLUDES = NEXT_INCLUDED_BY + ClangdIndexDataStorage::PTR_SIZE;
    const static int NEXT_INCLUDES = PREV_INCLUDES + ClangdIndexDataStorage::PTR_SIZE;
    const static int RECORD_SIZE = NEXT_INCLUDES + ClangdIndexDataStorage::PTR_SIZE;

    RecordPointer Record;
    ClangdIndexDataStorage &Storage;
    ClangdIndexStoreIndexer &Indexer;

  public:
    IndexStoreHeaderInclusion(ClangdIndexDataStorage &Storage,
        const IndexStoreFile& IncludedByFile,
        const IndexStoreFile& IncludedFile,
        ClangdIndexStoreIndexer &Indexer) :
        Storage(Storage), Indexer(Indexer) {
      Record = Storage.mallocRecord(RECORD_SIZE);
      Storage.putRecPtr(Record + INCLUDED_BY_FILE, IncludedByFile.getRecord());
      Storage.putRecPtr(Record + INCLUDED_FILE, IncludedFile.getRecord());
    }

    IndexStoreHeaderInclusion(ClangdIndexDataStorage &Storage,
        RecordPointer Record,
        ClangdIndexStoreIndexer &Indexer) :
        Record(Record), Storage(Storage), Indexer(Indexer) {
    }

    void setPrevIncludedBy(RecordPointer Rec) {
      Storage.putRecPtr(Record + PREV_INCLUDED_BY, Rec);
    }
    void setNextIncludedBy(RecordPointer Rec) {
      Storage.putRecPtr(Record + NEXT_INCLUDED_BY, Rec);
    }
    void setPrevInclusion(RecordPointer Rec) {
      Storage.putRecPtr(Record + PREV_INCLUDES, Rec);
    }
    void setNextInclusion(RecordPointer Rec) {
      Storage.putRecPtr(Record + NEXT_INCLUDES, Rec);
    }
    std::unique_ptr<IndexStoreFile> getIncluded () {
      return getPtrOrNull<IndexStoreFile>(Storage, Record + INCLUDED_FILE, Indexer);
    }

    std::unique_ptr<IndexStoreFile> getIncludedBy () {
      return getPtrOrNull<IndexStoreFile>(Storage, Record + INCLUDED_BY_FILE, Indexer);
    }

    std::unique_ptr<IndexStoreHeaderInclusion> getPrevIncludeBy() {
      return getPtrOrNull<IndexStoreHeaderInclusion>(Storage, Record + PREV_INCLUDED_BY, Indexer);
    }

    std::unique_ptr<IndexStoreHeaderInclusion> getNextIncludeBy() {
      return getPtrOrNull<IndexStoreHeaderInclusion>(Storage, Record + NEXT_INCLUDED_BY, Indexer);
    }

    std::unique_ptr<IndexStoreHeaderInclusion> getPrevInclusion() {
      return getPtrOrNull<IndexStoreHeaderInclusion>(Storage, Record + PREV_INCLUDES, Indexer);
    }

    std::unique_ptr<IndexStoreHeaderInclusion> getNextInclusion() {
      return getPtrOrNull<IndexStoreHeaderInclusion>(Storage, Record + NEXT_INCLUDES, Indexer);
    }

    RecordPointer getRecord() const {
      return Record;
    }
    void free() {
      Storage.freeRecord(Record);
    }
  };

  /**
   * Represents both headers and source files. There should be one
   * IndexStoreFile per file on the file system.
   */
  class IndexStoreFile {

    const static int PATH = 0;
    const static int FIRST_INCLUDED_BY = PATH + ClangdIndexDataStorage::PTR_SIZE;
    const static int FIRST_INCLUSION = FIRST_INCLUDED_BY + ClangdIndexDataStorage::PTR_SIZE;
    const static int RECORD_SIZE  = FIRST_INCLUSION + ClangdIndexDataStorage::PTR_SIZE;

    std::string Path;
    RecordPointer Record;
    ClangdIndexDataStorage &Storage;
    ClangdIndexStoreIndexer &Indexer;
  public:
    IndexStoreFile(ClangdIndexDataStorage &Storage, std::string Path, ClangdIndexStoreIndexer &Indexer) :
        Path(Path), Storage(Storage), Indexer(Indexer) {
      Record = Storage.mallocRecord(RECORD_SIZE);
      ClangdIndexString Str(Storage, Path);
      Storage.putRecPtr(Record + PATH, Str.getRecord());
    }
    IndexStoreFile(ClangdIndexDataStorage &Storage, RecordPointer Record, ClangdIndexStoreIndexer &Indexer) :
        Record(Record), Storage(Storage), Indexer(Indexer) {
      assert (Record >= ClangdIndexDataStorage::DATA_AREA);
    }

    const std::string& getPath() {
      if (Path.empty()) {
        std::string Str = ClangdIndexString(Storage,
            Storage.getRecPtr(Record + PATH)).getString();
        Path = Str;
      }
      return Path;
    }

    RecordPointer getRecord() const {
      return Record;
    }

    void setFirstIncludedBy(RecordPointer Rec) {
      Storage.putRecPtr(Record + FIRST_INCLUDED_BY, Rec);
    }
    void setFirstInclusion(RecordPointer Rec) {
      Storage.putRecPtr(Record + FIRST_INCLUSION, Rec);
    }

    void setLastIndexingTime(std::chrono::nanoseconds LastIndexingTime);
    std::chrono::nanoseconds getLastIndexingTime();

    std::unique_ptr<IndexStoreHeaderInclusion> getFirstIncludedBy() {
      return getPtrOrNull<IndexStoreHeaderInclusion>(Storage, Record + FIRST_INCLUDED_BY, Indexer);
    }

    std::unique_ptr<IndexStoreHeaderInclusion> getFirstInclusion() {
      return getPtrOrNull<IndexStoreHeaderInclusion>(Storage, Record + FIRST_INCLUSION, Indexer);
    }

    ClangdIndexDataStorage& getStorage() {
      return Storage;
    }
    void visitDependentFiles(std::function<bool(IndexStoreFile&)> Visitor);
    void visitInclusions(std::function<bool(IndexStoreFile&)> Visitor);
    void onChange();

    void free();

  private:
    void visitDependentFiles(std::function<bool(IndexStoreFile&)> Visitor,
        IndexStoreFile &File, std::set<RecordPointer> &VisitedFiles);
    void visitInclusions(std::function<bool(IndexStoreFile&)> Visitor,
        IndexStoreFile &File, std::set<RecordPointer> &VisitedFiles);

    void clearInclusions();
    void clearIncludedBys();
  };
private:

  class SymbolUSRComparator: public BTreeComparator {
    ClangdIndexDataStorage &MappingsDataStorage;
    indexstore::IndexStore &DataStore;

  public:
    SymbolUSRComparator(ClangdIndexDataStorage &MappingsDataStorage, indexstore::IndexStore &DataStore) :
      MappingsDataStorage(MappingsDataStorage), DataStore(DataStore) {
    }

    int compare(RecordPointer Record1, RecordPointer Record2) override {
      IndexStoreSymbol Symbol1(MappingsDataStorage, DataStore, Record1);
      IndexStoreSymbol Symbol2(MappingsDataStorage, DataStore, Record2);
      return Symbol1.getUsr().compare(Symbol2.getUsr());
    }
  };

  class SymbolNameComparator: public BTreeComparator {
    ClangdIndexDataStorage &MappingsDataStorage;
    indexstore::IndexStore &DataStore;

  public:
    SymbolNameComparator(ClangdIndexDataStorage &MappingsDataStorage, indexstore::IndexStore &DataStore) :
      MappingsDataStorage(MappingsDataStorage), DataStore(DataStore) {
    }

    int compare(RecordPointer Record1, RecordPointer Record2) override {
      IndexStoreSymbol Symbol1(MappingsDataStorage, DataStore, Record1);
      IndexStoreSymbol Symbol2(MappingsDataStorage, DataStore, Record2);
      int Compare = Symbol1.getName().compare(Symbol2.getName());
      if (Compare != 0) {
        return Compare;
      }

      if (Symbol1.getRecord() < Symbol2.getRecord())
        return -1;
      return 1;
    }
  };

  class RecordNameComparator: public BTreeComparator {
    ClangdIndexDataStorage &DataStorage;

  public:
    RecordNameComparator(ClangdIndexDataStorage &DataStorage) :
        DataStorage(DataStorage) {
    }

    int compare(RecordPointer Record1, RecordPointer Record2) override {
      IndexStoreRecord Rec1(DataStorage, Record1);
      IndexStoreRecord Rec2(DataStorage, Record2);
      return Rec1.getName().compare(Rec2.getName());
    }
  };

  class SymbolUSRVisitor: public BTreeVisitor {
    std::string Usr;
    ClangdIndexDataStorage &MappingsDataStorage;
    indexstore::IndexStore &DataStore;
    std::unique_ptr<IndexStoreSymbol> Result;

  public:
    SymbolUSRVisitor(std::string Usr, ClangdIndexDataStorage &MappingsDataStorage, indexstore::IndexStore &DataStore) :
        Usr(Usr), MappingsDataStorage(MappingsDataStorage), DataStore(DataStore) {
    }

    int compare(RecordPointer Record) override {
      IndexStoreSymbol Current(MappingsDataStorage, DataStore, Record);
      std::string CurrentUsr = Current.getUsr();
      return CurrentUsr.compare(Usr.c_str());
    }

    void visit(RecordPointer Record) override {
      assert(!Result);
      std::unique_ptr<IndexStoreSymbol> Current = llvm::make_unique<
          IndexStoreSymbol>(MappingsDataStorage, DataStore, Record);
      Result = std::move(Current);
    }

    std::unique_ptr<IndexStoreSymbol> getResult() {
      return std::move(Result);
    }
  };

  class SymbolRecordNameVisitor: public BTreeVisitor {
    std::string RecordName;
    ClangdIndexDataStorage &DataStore;
    std::unique_ptr<IndexStoreRecord> Result;

  public:
    SymbolRecordNameVisitor(std::string RecordName, ClangdIndexDataStorage &DataStore) :
      RecordName(RecordName), DataStore(DataStore) {
    }

    int compare(RecordPointer Record) override {
      IndexStoreRecord Current(DataStore, Record);
      std::string CurrentRecordName = Current.getName();
      return CurrentRecordName.compare(RecordName.c_str());
    }

    void visit(RecordPointer Record) override {
      assert(!Result);
      std::unique_ptr<IndexStoreRecord> Current = llvm::make_unique<
          IndexStoreRecord>(DataStore, Record);
      Result = std::move(Current);
    }

    std::unique_ptr<IndexStoreRecord> getResult() {
      return std::move(Result);
    }
  };

  class FileComparator: public BTreeComparator {

    ClangdIndexStoreIndexer &Indexer;

  public:
    FileComparator(ClangdIndexStoreIndexer &Indexer) :
      Indexer(Indexer) {
    }

    int compare(RecordPointer Record1, RecordPointer Record2) override {
      IndexStoreFile File1(Indexer.getMappingsStorage(), Record1, Indexer);
      IndexStoreFile File2(Indexer.getMappingsStorage(), Record2, Indexer);
      return File1.getPath().compare(File2.getPath());
    }
  };

  const static int VERSION = 1;
  const static int SYMBOLS_TREE_OFFSET;
  const static int RECORDS_TREE_OFFSET;
  const static int FILES_TREE_OFFSET;
  std::unique_ptr<ClangdIndexDataStorage> MappingsDataStorage;

  std::unique_ptr<SymbolUSRComparator> SymbolsUSRComparator;
  std::unique_ptr<SymbolNameComparator> SymbolsNameComparator;
  std::unique_ptr<RecordNameComparator> RecordNamesComparator;
  std::unique_ptr<FileComparator> FilesComparator;

  // USR to IndexStoreSymbol
  std::unique_ptr<BTree> Symbols;
  // Symbol name (TODO: qualified or not?) to IndexStoreSymbol
  std::unique_ptr<BTree> SymbolNames;
  // Filename to IndexStoreRecord
  std::unique_ptr<BTree> Records;
  // File path to IndexStoreFile
  std::unique_ptr<BTree> Files;

public:
  ClangdIndexStoreIndexer(std::string RootPath, GlobalCompilationDatabase& CDB);

  void onFileEvent(FileEvent Event) override;
  void indexRoot() override;
  void reindex() override;

  void foreachSymbols(StringRef Query, llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) override;
  void foreachSymbols(const USR &Usr, llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) override;

  void dumpIncludedBy(StringRef File) override;
  void dumpInclusions(StringRef File) override;
  std::unique_ptr<IndexStoreFile> getFile(StringRef FilePath);
  ClangdIndexDataStorage & getMappingsStorage() {
    return *MappingsDataStorage;
  }
  std::unique_ptr<IndexStoreFile> getOrCreateIndexStoreFile(StringRef FilePath);
  void addFile(IndexStoreFile &IndexFile) {
    Files->insert(IndexFile.getRecord());
  }
  void removeFile(IndexStoreFile &IndexFile) {
    assert(Files->remove(IndexFile.getRecord()));
  }

  //FIXME: this should not be public?
  std::unique_ptr<IndexStoreRecord> getRecord(StringRef Usr);
private:
  void foreachSymbols(const USR &Usr, llvm::function_ref<bool(std::unique_ptr<ClangdIndexDataSymbol>)> Receiver);
  void indexFile(StringRef File);
  std::unique_ptr<IndexStoreSymbol> getOrCreateSymbols(const USR &Usr, std::string Name, RecordPointer RecordFile);
  std::unique_ptr<IndexStoreRecord> getOrCreateIndexStoreRecord(StringRef RecordName);
  void collectOccurrences(StringRef File);
};

} /* namespace clangd */
} /* namespace clang */

#endif /* TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_INDEXSTORE_CLANGDINDEXSTOREDATABUILDER_H_ */
