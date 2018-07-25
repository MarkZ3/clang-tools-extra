#include "index/BTree.h"
#include "index/ClangdIndex.h"
#include "index/ClangdIndexDataProvider.h"
#include "index/ClangdIndexString.h"

#include "gtest/gtest.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

namespace {
const unsigned VERSION_NUM = 1;

std::string getTempStoragePath() {
  static llvm::SmallString<10> STORAGE_FILE_PATH;
  if (STORAGE_FILE_PATH.empty()) {
    llvm::SmallString<128> TmpDir;
    llvm::sys::path::system_temp_directory(/*erasedOnReboot=*/true, TmpDir);
    llvm::SmallString<128> TmpFile;
    llvm::sys::path::append(TmpFile, TmpDir, "test.index-%%%%%%%");
    llvm::sys::fs::createUniqueFile(TmpFile, STORAGE_FILE_PATH);
  }
  return STORAGE_FILE_PATH.str();
}

void deleteStorageFileIfExists(llvm::StringRef FilePath) {
  if (llvm::sys::fs::exists(FilePath))
    llvm::sys::fs::remove_directories(FilePath);
}
}

namespace clang {
namespace clangd {

class ClangdIndexDataStorageTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

TEST_F(ClangdIndexDataStorageTest, TestCreate) {
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    ASSERT_TRUE (llvm::sys::fs::exists(getTempStoragePath()));
    ASSERT_EQ(Storage.getVersion(), VERSION_NUM);
  }

  uint64_t FileSizeResult;
  ASSERT_EQ(llvm::sys::fs::file_size(getTempStoragePath(), FileSizeResult),
      std::error_code());
  ASSERT_EQ(FileSizeResult, ClangdIndexDataPiece::PIECE_SIZE);
}

TEST_F(ClangdIndexDataStorageTest, TestCreateReopenEmpty) {
  const unsigned EXPECTED_VERSION_NUM = 1234;
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), EXPECTED_VERSION_NUM);
    ASSERT_TRUE (llvm::sys::fs::exists(getTempStoragePath()));
    ASSERT_EQ(Storage.getVersion(), EXPECTED_VERSION_NUM);
    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), EXPECTED_VERSION_NUM);
    ASSERT_EQ(Storage.getVersion(), EXPECTED_VERSION_NUM);
  }
}

TEST_F(ClangdIndexDataStorageTest, TestReadWritePiece) {
  ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
  char BuffWrite[ClangdIndexDataPiece::PIECE_SIZE] = { '1', '2', '3' };
  BuffWrite [ClangdIndexDataPiece::PIECE_SIZE - 1] = '\0';
  Storage.writePiece(BuffWrite, 0);
  char BuffRead[ClangdIndexDataPiece::PIECE_SIZE];
  Storage.readPiece(BuffRead, 0);
  ASSERT_EQ(strcmp(BuffWrite, BuffRead), 0);
}

TEST_F(ClangdIndexDataStorageTest, TestMalloc) {
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    // Try to malloc all the valid sizes
    for (unsigned CurDataSize = 0;
        CurDataSize <= ClangdIndexDataStorage::MAX_MALLOC_SIZE; ++CurDataSize) {
      RecordPointer Rec = Storage.mallocRecord(CurDataSize);
      ASSERT_GE(Rec, ClangdIndexDataStorage::MALLOC_AREA_START);
    }
    Storage.endWrite();
    llvm::sys::fs::remove_directories(getTempStoragePath());
  }

  // Test reusing a free block that was left-over from previous malloc
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    // Choose a malloc size (and its header) that will fit nicely in a block
    // size. So we don't have to worry about rounding up to the next valid
    // block size
    const static unsigned int SMALL_MALLOC_SIZE = 10
        * ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT
        - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    const static unsigned int LEFT_OVER_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    // Make sure some assumptions about the constants are true
    ASSERT_TRUE(ClangdIndexDataStorage::MAX_MALLOC_SIZE > SMALL_MALLOC_SIZE
            && ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
                > ClangdIndexDataStorage::MIN_BLOCK_SIZE);
    RecordPointer Rec = Storage.mallocRecord(SMALL_MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    RecordPointer LeftOverMallocRec = Storage.mallocRecord(
        LEFT_OVER_MALLOC_SIZE);
    // If this malloc is right after the first one, we have successfully reused
    // a free block
    ASSERT_EQ(LeftOverMallocRec,
        Rec + ClangdIndexDataStorage::BLOCK_HEADER_SIZE + SMALL_MALLOC_SIZE);

    Storage.endWrite();
    llvm::sys::fs::remove_directories(getTempStoragePath());
  }

  // Test not reusing left-over from previous malloc because second malloc is
  // just too big
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    // Choose a malloc size (and its header) that will fit nicely in a block
    // size. So we don't have to worry about rounding up to the next valid
    // block size
    const static unsigned int SMALL_MALLOC_SIZE = 10
        * ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT
        - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    // Go a bit over the size that would fit in the free block
    const static unsigned int SECOND_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            + ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT;
    // Make sure some assumptions about the constants are true
    ASSERT_TRUE(ClangdIndexDataStorage::MAX_MALLOC_SIZE > SMALL_MALLOC_SIZE
            && ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
                > ClangdIndexDataStorage::MIN_BLOCK_SIZE);
    RecordPointer Rec = Storage.mallocRecord(SMALL_MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    RecordPointer SecondMallocRec = Storage.mallocRecord(SECOND_MALLOC_SIZE);
    ASSERT_EQ(SecondMallocRec, Rec + ClangdIndexDataStorage::MAX_BLOCK_SIZE);

    Storage.endWrite();
    llvm::sys::fs::remove_directories(getTempStoragePath());
  }

  // Test linked list of free blocks. Do mallocs so that two free blocks of the
  // same size are created than malloc so they are used in order.
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    // Choose a malloc size (and its header) that will fit nicely in a block
    // size. So we don't have to worry about rounding up to the next valid
    // block size
    const static unsigned int BIG_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_BLOCK_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            - 10 * ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT;
    // Size that would have fit without considering the min block size
    // necessary for the left over free block
    const static unsigned int LEFT_OVER_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_MALLOC_SIZE - BIG_MALLOC_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    // Make sure some assumptions about the constants are true
    ASSERT_TRUE(ClangdIndexDataStorage::MAX_MALLOC_SIZE > BIG_MALLOC_SIZE
            && ClangdIndexDataStorage::MAX_MALLOC_SIZE - BIG_MALLOC_SIZE
                >= ClangdIndexDataStorage::MIN_BLOCK_SIZE);
    RecordPointer RecMalloc1 = Storage.mallocRecord(BIG_MALLOC_SIZE);
    ASSERT_EQ(RecMalloc1, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    RecordPointer RecMalloc2 = Storage.mallocRecord(BIG_MALLOC_SIZE);
    ASSERT_EQ(RecMalloc2, RecMalloc1 + ClangdIndexDataStorage::MAX_BLOCK_SIZE);
    RecordPointer LeftOver1Rec = Storage.mallocRecord(LEFT_OVER_MALLOC_SIZE);
    // The last free block is the first in the linked list of free blocks of
    // that size
    ASSERT_EQ(LeftOver1Rec,
        RecMalloc2 + ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            + BIG_MALLOC_SIZE);
    RecordPointer LeftOver2Rec = Storage.mallocRecord(LEFT_OVER_MALLOC_SIZE);
    ASSERT_EQ(LeftOver2Rec,
        RecMalloc1 + ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            + BIG_MALLOC_SIZE);
    // No free block left
    RecordPointer LeftOver3Rec = Storage.mallocRecord(LEFT_OVER_MALLOC_SIZE);
    ASSERT_EQ(LeftOver3Rec,
        RecMalloc2 + ClangdIndexDataStorage::MAX_BLOCK_SIZE);

    Storage.endWrite();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetInt8) {
  RecordPointer Rec;
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    Rec = Storage.mallocRecord(sizeof(int8_t) * 3);
    Storage.putInt8(Rec, INT8_MIN);
    Storage.putInt8(Rec + sizeof(int8_t), INT8_MAX);
    Storage.putInt8(Rec + sizeof(int8_t) * 2, 0);

    ASSERT_EQ(Storage.getInt8(Rec), INT8_MIN);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t)),
        INT8_MAX);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t) * 2),
        0);
    Storage.endWrite();

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);

    ASSERT_EQ(Storage.getInt8(Rec), INT8_MIN);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t)), INT8_MAX);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t) * 2), 0);
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetInt32) {
  RecordPointer Rec;
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    Rec = Storage.mallocRecord(ClangdIndexDataStorage::INT32_SIZE * 3);
    Storage.putInt32(Rec, INT32_MIN);
    Storage.putInt32(Rec + ClangdIndexDataStorage::INT32_SIZE, INT32_MAX);
    Storage.putInt32(Rec + ClangdIndexDataStorage::INT32_SIZE * 2, 0);

    ASSERT_EQ(Storage.getInt32(Rec), INT32_MIN);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE),
        INT32_MAX);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE * 2),
        0);
    Storage.endWrite();

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);

    ASSERT_EQ(Storage.getInt32(Rec), INT32_MIN);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE),
        INT32_MAX);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE * 2),
        0);
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetData) {
  struct MyDataStruct {
    int Foo;
    int Bar;
  };
  MyDataStruct ObjPut;
  ObjPut.Foo = 0xABCD;
  ObjPut.Bar = 0xEF01;

  RecordPointer Rec;
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    Rec = Storage.mallocRecord(sizeof(MyDataStruct));
    Storage.putData(Rec, &ObjPut, sizeof(MyDataStruct));

    MyDataStruct ObjGet;
    Storage.getData(Rec, &ObjGet, sizeof(MyDataStruct));
    ASSERT_EQ(ObjGet.Foo, ObjPut.Foo);
    ASSERT_EQ(ObjGet.Bar, ObjPut.Bar);
    Storage.endWrite();

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);

    MyDataStruct ObjGet;
    Storage.getData(Rec, &ObjGet, sizeof(MyDataStruct));
    ASSERT_EQ(ObjGet.Foo, ObjPut.Foo);
    ASSERT_EQ(ObjGet.Bar, ObjPut.Bar);
    Storage.endWrite();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestStartEndWrite) {
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    //Commented this out because it caused crash reporters to show every time
    //the test was executed. Not sure what the best practice for this is.
    //ASSERT_DEATH_IF_SUPPORTED(Storage.mallocRecord(1), ".*write mode*.");

    // Shouldn't do anything, write not started
    Storage.endWrite();

    Storage.startWrite();
    RecordPointer Rec1 = Storage.mallocRecord(
        ClangdIndexDataStorage::MAX_MALLOC_SIZE);
    Storage.putInt32(Rec1, 123);
    Storage.endWrite();
    ASSERT_EQ(Storage.getInt32(Rec1), 123);

    // Flush can be called before end of write, the index will still be in
    // write mode
    Storage.startWrite();
    RecordPointer Rec2 = Storage.mallocRecord(
        ClangdIndexDataStorage::MAX_MALLOC_SIZE);
    Storage.putInt32(Rec2, 456);
    Storage.flush();
    RecordPointer Rec3 = Storage.mallocRecord(
        ClangdIndexDataStorage::MAX_MALLOC_SIZE);
    Storage.putInt32(Rec3, 789);
    Storage.endWrite();
    ASSERT_EQ(Storage.getInt32(Rec2), 456);
    ASSERT_EQ(Storage.getInt32(Rec3), 789);

    Storage.flush();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestFree) {
  // A simple malloc, delete, then malloc should end up at the same spot
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    const static unsigned MALLOC_SIZE =
        ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT * 10
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    RecordPointer Rec = Storage.mallocRecord(MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    Storage.freeRecord(Rec);
    Rec = Storage.mallocRecord(MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);

    Storage.endWrite();
    llvm::sys::fs::remove_directories(getTempStoragePath());
  }

  // Malloc all possible sizes, delete all, then mallocs should end up reusing
  // all free blocks
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    // Try to malloc all the valid sizes
    std::vector<RecordPointer> Records;
    RecordPointer MaxRecord;
    for (unsigned CurDataSize = 0;
        CurDataSize <= ClangdIndexDataStorage::MAX_MALLOC_SIZE; ++CurDataSize) {
      RecordPointer Rec = Storage.mallocRecord(CurDataSize);
      ASSERT_GE(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
              + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
      Records.push_back(Rec);
      MaxRecord = std::max(Rec, MaxRecord);
    }

    // Delete everything
    for (auto Rec : Records) {
      Storage.freeRecord(Rec);
    }

    // Realloc everything, they should all fit in previously freed blocks
    // (<= MaxRecord from previous).
    for (unsigned CurDataSize = 0;
        CurDataSize <= ClangdIndexDataStorage::MAX_MALLOC_SIZE; ++CurDataSize) {
      RecordPointer Rec = Storage.mallocRecord(CurDataSize);
      ASSERT_GE(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
              + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
      ASSERT_LE(Rec, MaxRecord);
      if (CurDataSize == 0) {
        break;
      }
    }

    Storage.endWrite();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetRec) {
  const int32_t SOME_INT_VALUE = 1245678;

  // Malloc an integer, make a pointer to it
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    RecordPointer Rec = Storage.mallocRecord(
        ClangdIndexDataStorage::INT32_SIZE);
    Storage.putInt32(Rec, SOME_INT_VALUE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    Storage.putRecPtr(ClangdIndexDataStorage::DATA_AREA, Rec);
    Storage.endWrite();
    Storage.flush();
  }

  // Read back the int using the pointer
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    RecordPointer RecPtr = Storage.getRecPtr(ClangdIndexDataStorage::DATA_AREA);
    ASSERT_EQ(Storage.getInt32(RecPtr), SOME_INT_VALUE);
  }
}

class ClangdIndexStringTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

TEST_F(ClangdIndexStringTest, TestPutGetString) {
  std::vector<RecordPointer> Records;
  std::vector<std::string> WrittenStrings;
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();

    // Try to write strings of all the valid sizes
    for (unsigned CurStringSize = 0;
        CurStringSize <= ClangdIndexString::MAX_STRING_SIZE; ++CurStringSize) {
      std::vector<char> Str(CurStringSize + 1);
      Str[CurStringSize] = '\0';
      // Write some characters
      for (unsigned I = 0; I < CurStringSize; ++I) {
        Str[I] = 'A';
      }

      std::string CurString(Str.data());
      RecordPointer Rec = ClangdIndexString(Storage, CurString).getRecord();
      // Make sure we can read back the string we just created
      ASSERT_EQ(ClangdIndexString(Storage, Rec).getString().compare(CurString),
          0);

      // Save those for later when we reopen the file
      Records.push_back(Rec);
      WrittenStrings.push_back(CurString);
    }

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);

    // Make sure all the strings are there after reopening the file
    for (size_t I = 0; I < Records.size(); ++I) {
      // Make sure we can read back the string we just created
      ASSERT_EQ(ClangdIndexString(Storage, Records[I]).getString().compare(
              WrittenStrings[I]), 0);
    }

    Storage.flush();
  }
}
TEST_F(ClangdIndexStringTest, TestLargeString) {
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    unsigned Length = ClangdIndexString::MAX_STRING_SIZE + 2;
    std::vector<char> Str(Length);
    for (unsigned I = 0; I < Length; ++I) {
      Str[I] = 'A';
    }
    Str[Length] = '\0';
    //Commented this out because it caused crash reporters to show every time
    //the test was executed. Not sure what the best practice for this is.
    //ASSERT_DEATH_IF_SUPPORTED(ClangdIndexString(Storage, Str.data()),
    //    ".*not supported.*");

    Storage.flush();
  }
}

class ClangdBTreeTest : public ::testing::Test {

  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

class StringComparator : public BTreeComparator {
  ClangdIndexDataStorage &Storage;

public:
  StringComparator(ClangdIndexDataStorage &Storage) : Storage(Storage) {
  }

  int compare(RecordPointer Record1, RecordPointer Record2) override {
    std::string Str1 = ClangdIndexString(Storage, Record1).getString();
    std::string Str2 = ClangdIndexString(Storage, Record2).getString();
    return Str1.compare(Str2);
  }
};

class StringVisitor: public BTreeVisitor {

  std::string SearchedString;
  ClangdIndexDataStorage &Storage;
  bool IsFound;
  RecordPointer Result;

public:
  StringVisitor(std::string SearchedString, ClangdIndexDataStorage &Storage) :
      SearchedString(SearchedString), Storage(Storage), IsFound(false), Result(
          0) {
  }

  int compare(RecordPointer Record) override {
    std::string Current = ClangdIndexString(Storage, Record).getString();
    return Current.compare(SearchedString);
  }

  void visit(RecordPointer Record) override {
    IsFound = true;
    Result = Record;
  }

  bool isFound() {
    return IsFound;
  }

  RecordPointer getResult() {
    return Result;
  }
};

TEST_F(ClangdBTreeTest, TestInsert) {
  // Insert a number of strings and check if there are present after
  const int NUM_CHECKED = 1000;
  std::string TEST_STRING_PREFIX = "string";
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      ClangdIndexString Str(Storage, SS.str());
      Tree.insert(Str.getRecord());
    }
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      StringVisitor Visitor(SS.str(), Storage);
      Tree.accept(Visitor);
      ASSERT_TRUE(Visitor.isFound());
    }
  }
}

TEST_F(ClangdBTreeTest, TestInsertSimple) {
  // Insert a number of strings and check if there are present after
  std::string TEST_STRING_PREFIX = "string";
  ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
  Storage.startWrite();
  StringComparator Comp(Storage);
  BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 2);
  std::vector<std::string> Letters =
      { "A", "B", "C", "D", "E", "F" };
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
}

TEST_F(ClangdBTreeTest, TestInsertMuchMore) {
  // Insert a number of strings and check if there are present after
  const int NUM_CHECKED = 50000;
  std::string TEST_STRING_PREFIX = "string";
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      ClangdIndexString Str(Storage, SS.str());
      Tree.insert(Str.getRecord());

      for (int J = 0; J <= 0; ++J) {
        std::stringstream SS2;
        SS2 << TEST_STRING_PREFIX << J;
        StringVisitor Visitor(SS2.str(), Storage);
        Tree.accept(Visitor);
        bool found = Visitor.isFound();
        if (!found) {
          std::cerr << SS2.str() << std::endl;
        }
        ASSERT_TRUE(found);
      }
    }
    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 1; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      StringVisitor Visitor(SS.str(), Storage);
      Tree.accept(Visitor);
      bool found = Visitor.isFound();
      if (!found) {
        std::cerr << SS.str() << std::endl;
      }
      ASSERT_TRUE(found);
    }

    // Also test that we can match all of them with a "multi match" visitor.

    class AllMatch : public BTreeVisitor {
      int Total = 0;
    public:
      int compare(RecordPointer Record) override {
        return 0;
      }
      void visit(RecordPointer Record) override {
        Total++;
      }
      int getTotal() {
        return Total;
      }
    };
    AllMatch V;
    Tree.accept(V);
    ASSERT_EQ(V.getTotal(), NUM_CHECKED);
  }
}

TEST_F(ClangdBTreeTest, TestInsertBackwards) {
  // Insert a number of strings and check if there are present after.
  // This inserts them backwards as this will it hit different code paths.
  const int NUM_CHECKED = 1000;
  std::string TEST_STRING_PREFIX = "string";
  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = NUM_CHECKED - 1; I >= 0; --I) {
      std::stringstream ss;
      ss << TEST_STRING_PREFIX << I;
      ClangdIndexString Str = ClangdIndexString(Storage, ss.str());
      Tree.insert(Str.getRecord());
    }
  }

  {
    ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      StringVisitor Visitor(SS.str(), Storage);
      Tree.accept(Visitor);
      ASSERT_TRUE(Visitor.isFound());
    }
  }
}

void testStringDeletion(std::string StringToDelete,
    std::vector<std::string> &CurrentStrings, BTree &Tree,
    ClangdIndexDataStorage &Storage) {
  StringVisitor SV(StringToDelete, Storage);
  Tree.accept(SV);
  std::string FoundString =
      ClangdIndexString(Storage, SV.getResult()).getString();
  if (!SV.isFound()) {
    std::cerr << " string not found in tree: " << StringToDelete << "\n";
  }
  ASSERT_TRUE(SV.isFound());
  ASSERT_EQ(StringToDelete, FoundString);
  ASSERT_TRUE(Tree.remove(SV.getResult()));

  StringVisitor SVDeleted(StringToDelete, Storage);
  Tree.accept(SVDeleted);
  ASSERT_FALSE(SVDeleted.isFound());
  CurrentStrings.erase(std::remove(CurrentStrings.begin(), CurrentStrings.end(),
          StringToDelete));

  // Make sure all the other letters are still there
  for (auto Letter : CurrentStrings) {
    StringVisitor SV(Letter, Storage);
    Tree.accept(SV);
    std::string FoundString =
        ClangdIndexString(Storage, SV.getResult()).getString();
    ASSERT_TRUE(SV.isFound());
    ASSERT_EQ(Letter, FoundString);
  }
}

TEST_F(ClangdBTreeTest, TestRemove) {
  ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
  Storage.startWrite();

  StringComparator Comp(Storage);
  BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 3);

  // Remove on empty tree. Nothing should happen.
  ASSERT_FALSE(Tree.remove(0));

  std::vector<std::string> Letters =
      { "D", "E", "G", "J", "K", "M", "N", "O", "P", "R", "S", "X", "Y", "Z",
          "V", "A", "C", "T", "U", "B", "Q", "L", "F" };
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }

  // Delete F, case 1: Simple deletion from a leaf
  testStringDeletion("F", Letters, Tree, Storage);

  // Delete M, case 2a: key found in currently visited internal node. Find a
  // key in *previous* node to replace it.
  testStringDeletion("M", Letters, Tree, Storage);

  // Delete G, case 2c: key found in currently visited internal node,
  // previous and next child nodes don't have enough keys to give one away.
  // Merge key and next child node into previous child node then delete key.
  testStringDeletion("G", Letters, Tree, Storage);

  // Delete D, case 3b: key not found in currently visited internal node.
  // The next node to be visited doesn't contain enough keys.
  // Both sibling nodes (only one in case of left-most or right-most) don't have
  // enough keys to give one away.
  // Merge key and sibling with next node then recurse into it.
  testStringDeletion("D", Letters, Tree, Storage);

  // Delete B, case 3a: key not found in currently visited internal node.
  // The next node to be visited doesn't contain enough keys. One of the sibling
  // nodes has enough keys to give one away.
  // Push up the given away key to current node and push down a key do next node
  // then recurse into it. This case is the *next* sibling has extra keys to
  // give away.
  testStringDeletion("B", Letters, Tree, Storage);

  // Delete U, case 3a, symmetrical case: *previous* sibling has extra keys to
  // give away.
  testStringDeletion("U", Letters, Tree, Storage);

  // Delete Z, case 3b, key in right-most child node
  testStringDeletion("Z", Letters, Tree, Storage);

  // Delete V, case 1
  testStringDeletion("V", Letters, Tree, Storage);

  // Delete S, case 2b: key found in currently visited internal node. Find a
  // key in *next* node to replace it.
  testStringDeletion("S", Letters, Tree, Storage);

  // Delete X, case 3b
  testStringDeletion("X", Letters, Tree, Storage);

  // Delete more things to get to next case (2c with new root)
  testStringDeletion("A", Letters, Tree, Storage);
  testStringDeletion("C", Letters, Tree, Storage);
  testStringDeletion("E", Letters, Tree, Storage);
  testStringDeletion("J", Letters, Tree, Storage);
  testStringDeletion("K", Letters, Tree, Storage);
  testStringDeletion("L", Letters, Tree, Storage);
  testStringDeletion("N", Letters, Tree, Storage);
  testStringDeletion("O", Letters, Tree, Storage);
  // The tree should now be like this:
  //
  //      |
  //    Y
  //      |
  //    T
  //      |
  //R
  //      |
  //    Q
  //      |
  //    P
  //      |
  // Case 2c with new root
  testStringDeletion("R", Letters, Tree, Storage);

  std::vector<std::string> Copy = Letters;
  // Delete everything remaining
  for (auto Letter : Copy) {
    testStringDeletion(Letter, Letters, Tree, Storage);
  }

  // Test delete non-existent
  ClangdIndexString Str(Storage, "A");
  ASSERT_FALSE(Tree.remove(Str.getRecord()));


  // Make a new set of letters for more tests
  Letters =
      { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
          "O", "P", "Q", "R", "S", "T", "U"};
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
  // 2b but in this case, finding the lowest key has to go through multiple
  // internal nodes. So this tests the algorithm for proper recursion.
  testStringDeletion("I", Letters, Tree, Storage);
  std::vector<std::string> MoreLetter = {"H1", "H2", "H3", "H4"};
  Letters.insert(Letters.end(), MoreLetter.begin(), MoreLetter.end());
  for (auto Letter : MoreLetter) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
  // 2a but in this case, finding the highest key has to go through multiple
  // internal nodes. So this tests the algorithm for proper recursion.
  testStringDeletion("J", Letters, Tree, Storage);

  Storage.endWrite();
}

TEST_F(ClangdBTreeTest, TestDump) {
  ClangdIndexDataStorage Storage(getTempStoragePath(), VERSION_NUM);
  Storage.startWrite();

  StringComparator Comp(Storage);
  BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 3);

  //Dump initially empty tree. Should result in empty string stream.
  std::string StreamBuffer;
  llvm::raw_string_ostream Stream(StreamBuffer);
  Tree.dump([](RecordPointer Rec, llvm::raw_ostream &OS) {OS << "A";}, Stream);
  ASSERT_TRUE(Stream.str().empty());

  std::vector<std::string> Letters =
      { "D", "E", "G", "J", "K", "M", "N", "O", "P", "R", "S", "X", "Y", "Z",
          "V", "A", "C", "T", "U", "B", "Q", "L" };
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
  Tree.dump([&Storage](RecordPointer Rec, llvm::raw_ostream &OS) {
    OS << ClangdIndexString(Storage, Rec).getString();
  }, Stream);
  ASSERT_TRUE(!Stream.str().empty());

  // Test empty but initialized (non-null root node)
  for (auto Letter : Letters) {
    StringVisitor SV(Letter, Storage);
    Tree.accept(SV);
    RecordPointer Result = SV.getResult();
    ASSERT_NE(Result, 0);
    ASSERT_TRUE(Tree.remove(SV.getResult()));
  }

  std::string StreamBuffer2;
  llvm::raw_string_ostream Stream2(StreamBuffer2);
  Tree.dump([&Storage](RecordPointer Rec, llvm::raw_ostream &OS) {
    OS << ClangdIndexString(Storage, Rec).getString();
  }, Stream2);
  ASSERT_TRUE(!Stream2.str().empty());

  Storage.endWrite();
}

class ClangdIndexSymbolTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

TEST_F(ClangdIndexSymbolTest, TestCreateAndGetters) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");

  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Symbol = std::move(Symbols[0]);
    ASSERT_TRUE(Symbol);
    ASSERT_EQ(Symbol->getUsr(), TEST_USR);
    ASSERT_FALSE(Symbol->getFirstOccurrence());
    ASSERT_NE(Symbol->getRecord(), 0);
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Symbol = std::move(Symbols[0]);
    ASSERT_TRUE(Symbol);
    ASSERT_EQ(Symbol->getUsr(), TEST_USR);
    ASSERT_FALSE(Symbol->getFirstOccurrence());
    ASSERT_NE(Symbol->getRecord(), 0);
  }
}


class ClangdIndexOccurrenceTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

TEST_F(ClangdIndexOccurrenceTest, TestCreateAndGetters) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");
  const IndexSourceLocation LOC_START = 12;
  const IndexSourceLocation LOC_END = 23;

  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));


    IndexFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Occurrence = Symbols[0]->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_NE(Occurrence->getRecord(), 0);
    ASSERT_EQ(Occurrence->getPath(), TEST_FILE_PATH);
    ASSERT_EQ(Occurrence->getLocStart(), LOC_START);
    ASSERT_EQ(Occurrence->getLocEnd(), LOC_END);
    ASSERT_FALSE(Occurrence->getNextInFile());
    ASSERT_FALSE(Occurrence->getNextOccurrence());
    ASSERT_EQ(Occurrence->getRoles(), static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Occurrence = Symbols[0]->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_NE(Occurrence->getRecord(), 0);
    ASSERT_EQ(Occurrence->getPath(), TEST_FILE_PATH);
    ASSERT_EQ(Occurrence->getLocStart(), LOC_START);
    ASSERT_EQ(Occurrence->getLocEnd(), LOC_END);
    ASSERT_FALSE(Occurrence->getNextInFile());
    ASSERT_FALSE(Occurrence->getNextOccurrence());
    ASSERT_EQ(Occurrence->getRoles(), static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
  }
}


class ClangdIndexFileTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

TEST_F(ClangdIndexFileTest, TestCreateAndGetters) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    ASSERT_EQ(FileGet->getPath(), TEST_FILE_PATH);
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    ASSERT_EQ(File->getPath(), TEST_FILE_PATH);
  }
}

TEST_F(ClangdIndexFileTest, TestAddOccurrence) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");
  const USR TEST_BAD_USR("c#bar#");
  const IndexSourceLocation LOC_START = 12;
  const IndexSourceLocation LOC_END = 23;

  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));

    IndexFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    ASSERT_NE(FileGet->getRecord(), 0);
    auto Occurrence = FileGet->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_FALSE(FileGet->getFirstIncludedBy());
    ASSERT_FALSE(FileGet->getFirstInclusion());

    ASSERT_FALSE(Index.getFile(TEST_USR.str()));
    ASSERT_TRUE(Index.getDefinitions(StringRef(TEST_FILE_PATH)).empty());
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    ASSERT_NE(File->getRecord(), 0);
    auto Occurrence = File->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_FALSE(File->getFirstIncludedBy());
    ASSERT_FALSE(File->getFirstInclusion());

    ASSERT_FALSE(Index.getFile(TEST_USR.str()));
    ASSERT_TRUE(Index.getDefinitions(StringRef(TEST_FILE_PATH)).empty());
  }
}

TEST_F(ClangdIndexFileTest, TestOnChange) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");
  const IndexSourceLocation LOC_START = 12;
  const IndexSourceLocation LOC_END = 23;

  // Very simple case. No occurrence in the file.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    Index.addFile(*IndexFile);

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getSymbols(TEST_USR).empty());
    IndexFile->onChange();

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getSymbols(TEST_USR).empty());
  }
  llvm::sys::fs::remove_directories(getTempStoragePath());

  // Simple case. Symbol with only one occurrence in one file.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));

    IndexFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    ASSERT_TRUE(IndexFile->getFirstOccurrence());
    ASSERT_FALSE(Index.getSymbols(TEST_USR).empty());
    IndexFile->onChange();

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getSymbols(TEST_USR).empty());
  }
  llvm::sys::fs::remove_directories(getTempStoragePath());

  // Symbol with a reference in one file and a definition in another file.
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexHeaderFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH + ".h", Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);

    // Add definition
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexHeaderFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
    IndexHeaderFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);

    // Add reference
    auto IndexReferenceOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Reference));
    IndexFile->addOccurrence(*IndexReferenceOccurrence);
    IndexSymbol->addOccurrence(*IndexReferenceOccurrence);

    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);
    Index.addFile(*IndexHeaderFile);

    ASSERT_TRUE(IndexFile->getFirstOccurrence());
    ASSERT_EQ(Index.getSymbols(TEST_USR).size(), 1u);
    ASSERT_EQ(Index.getDefinitions(TEST_USR).size(), 1u);
    ASSERT_EQ(Index.getReferences(TEST_USR).size(), 2u);

    IndexFile->onChange();

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(IndexHeaderFile->getFirstOccurrence());
    ASSERT_EQ(Index.getDefinitions(TEST_USR).size(), 1u);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Symbol = std::move(Symbols[0]);
    auto Occurrence = Symbol->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_FALSE(Occurrence->getNextInFile());
    ASSERT_FALSE(Occurrence->getNextOccurrence());
    ASSERT_EQ(Index.getReferences(TEST_USR).size(), 1u);

    IndexHeaderFile->onChange();
    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_FALSE(IndexHeaderFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getDefinitions(TEST_USR).empty());
    ASSERT_TRUE(Index.getReferences(TEST_USR).empty());
  }
}

class ClangdIndexTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists(getTempStoragePath());
  }
};

TEST_F(ClangdIndexTest, TestCreate) {
  {
    ClangdIndex Index(getTempStoragePath());
    ASSERT_TRUE (llvm::sys::fs::exists(getTempStoragePath()));
  }

  uint64_t FileSizeResult;
  ASSERT_EQ(llvm::sys::fs::file_size(getTempStoragePath(), FileSizeResult),
      std::error_code());
  ASSERT_NE(FileSizeResult, 0u);
}

TEST_F(ClangdIndexTest, TestAddGetFile) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  {
    ClangdIndex Index(getTempStoragePath());
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    Index.addFile(*IndexFile);
    ASSERT_TRUE(Index.getFile(TEST_FILE_PATH));
    ASSERT_FALSE(Index.getFile("/bar.cpp"));
    Index.getStorage().endWrite();
  }

  {
    ClangdIndex Index(getTempStoragePath());
    ASSERT_TRUE(Index.getFile(TEST_FILE_PATH));
    ASSERT_FALSE(Index.getFile("/bar.cpp"));
  }
}

} // namespace clangd
} // namespace clang
