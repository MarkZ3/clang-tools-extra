//===--- ClangdIndexDataStorage.cpp - Index storage code ------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATASTORAGE_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATASTORAGE_H

#include "ClangdIndexDataPiece.h"

#include "llvm/ADT/STLExtras.h"

#include <deque>
#include <fstream>
#include <memory>
#include <vector>

namespace clang {
namespace clangd {

// Defined outside class to be able to use it to initialize some static members.
constexpr static int blockSizeToFreeBlockEntryOffsetConstExpr(int Blocksize,
    int MIN_BLOCK_SIZE, int BLOCK_SIZE_INCREMENT, int PTR_SIZE,
    int FREE_BLOCK_TABLE_START) {
  // This equation looks a bit curious but is clearer when looking at the file
  // layout below.
  return (Blocksize - MIN_BLOCK_SIZE) / BLOCK_SIZE_INCREMENT * PTR_SIZE
      + FREE_BLOCK_TABLE_START;
}

/*
 This utility provides a malloc-like interface for writing data to a file.
 Clients can allocate memory by calling "malloc" and a file pointer will be
 returned. Similarly, memory can be freed with "free". "Blocks" are allocated
 and freed transparently.

 -- Structure --

 The file layout looks like this:

 0       | File version
 ________|____________Start of free block pointer table___
 4       | Free Block Pointer (for free blocks of  8 bytes)
 8       | Free Block Pointer (for free blocks of 16 bytes)
 12      | Free Block Pointer (for free blocks of 24 bytes)
 ...
 2048    | Free Block Pointer (for free blocks of 4096 bytes)
 ________|____________User data start______________________
 2052    | User data


 There are two types of blocks. Free blocks and data blocks.
 The block size can vary from 8 bytes (MIN_BLOCK_SIZE) to 4096 bytes
 (MAX_BLOCK_SIZE).

 -- Free blocks --

 The free blocks are tracked in a table of pointers to free block (see file
 layout above). Free blocks can link to other free blocks of the same size,
 therefore, an entry in the table is a linked list of free blocks of a given
 size. The index in the table is directly related to the size of the free
 block. Blocks are allocated and tracked in increment of 8 bytes
 (BLOCK_SIZE_INCREMENT).

 The relationship between free block size and its entry offset is:
 Size = (Offset - 4) / 4 * 8 + 8
 And therefore the offset of a free block entry is:
 Offset = (Size - 8) / 8 * 4 + 4

 The free block layout looks like this

 0         | Free block size (i.e. 8 to 4096)
 2         | Pointer to next free block of the same size
 6 to size | Unused (until it becomes a data block)
 __________|___________________________________________

 -- Data blocks --

 When a free block is chosen to be used for data, it becomes a data block with
 a structure that looks like this:

 0         | Block size (i.e. 8 to 4096)
 2 to size | Any ("user") data
 __________|___________________________________________

 Therefore, the maximum malloc-able data size is 4094 because 2 bytes is
 reserved for the size of the block.

 -- Caching --

 The file is read in "pieces" of 4096 bytes and can be put into a cache. When
 the pieces are "flushed", then they are written to disk (if they are dirty).
 Pieces are only for caching purposes and have no physical representation on
 disk.
 */
class ClangdIndexDataStorage {
public:
  const static unsigned INT32_SIZE = sizeof(int32_t); //: 4
private:
  const static unsigned VERSION_OFFSET = 0;
  const static unsigned FREE_BLOCK_TABLE_START = INT32_SIZE;

public:
  const static unsigned BLOCK_SIZE_INCREMENT = 8;
  const static unsigned BLOCK_SIZE_INCREMENT_BITS = 3;
  const static unsigned BLOCK_HEADER_SIZE = sizeof(int16_t);
private:

  const static unsigned DATA_BLOCK_SIZE_OFFSET = 0;

  const static unsigned FREE_BLOCK_SIZE_OFFSET = DATA_BLOCK_SIZE_OFFSET;
  const static unsigned FREE_BLOCK_NEXT_OFFSET = FREE_BLOCK_SIZE_OFFSET
      + BLOCK_HEADER_SIZE; //: 2
  const static unsigned FREE_BLOCK_SIZE = FREE_BLOCK_NEXT_OFFSET +
      INT32_SIZE; //: 6

public:
  const static unsigned MIN_BLOCK_SIZE = (FREE_BLOCK_SIZE + BLOCK_SIZE_INCREMENT
      - 1) / BLOCK_SIZE_INCREMENT * BLOCK_SIZE_INCREMENT; //: 8
  const static unsigned MAX_BLOCK_SIZE =
      ClangdIndexDataPiece::PIECE_SIZE; //: 4096
  const static unsigned MAX_MALLOC_SIZE = MAX_BLOCK_SIZE
      - BLOCK_HEADER_SIZE; //: 4094
  // In order to make the maximum bigger, we use the fact that block addresses
  // are aligned on BLOCK_SIZE_INCREMENT, therefore some bits
  // (BLOCK_SIZE_INCREMENT_BITS) are always 0 and free to use. So addresses
  // are 35 bit wide but can compressed to 32 bits (int32).
  const static RecordPointer MAX_STORAGE_ADDRESS = ((RecordPointer) 1
      << (INT32_SIZE * 8 + BLOCK_SIZE_INCREMENT_BITS));  //: 34359738368
  const static unsigned MAX_PIECE_ID = MAX_STORAGE_ADDRESS
      / ClangdIndexDataPiece::PIECE_SIZE;
private:

  struct DataBlock {
    ClangdIndexDataStorage& Storage;
    RecordPointer Record;
    DataBlock(ClangdIndexDataStorage& Storage, RecordPointer Rec);
    DataBlock(ClangdIndexDataStorage& Storage, unsigned MinimumNeededBlockSize);
    RecordPointer getUserDataRecPointer() const;
    int16_t getSize();
    void free();
  };

  struct FreeBlock {
    ClangdIndexDataStorage& Storage;
    RecordPointer Record;

    FreeBlock(ClangdIndexDataStorage& Storage, RecordPointer Rec);
    FreeBlock(ClangdIndexDataStorage& Storage, RecordPointer Rec, int Blocksize,
        bool AddToFreeBlockTable);
    void Remove();
    void convertIntoDataBlock(unsigned RequestedSize);
    int16_t getSize();
  };

  std::fstream FileStream;
  bool WriteMode;
  unsigned Version;
  //bool Valid;
  std::string LastError;

  // Holds the the version, free block table.
  // Therefore, we always keep it in memory.
  ClangdIndexDataPieceRef HeaderDataPiece;
  // Table of all to pieces (shared pointers).
  // -While writing (WriteMode), all pieces being written are kept in this table
  // until the index is flushed.
  // -While reading-only, only cached pieces are kept.
  std::vector<ClangdIndexDataPieceRef> Pieces;
  // A list of cached pieces (Piece ID). Used to choose which one to release
  // when the cache is full. Pieces in the cache can be held even after a
  // flush.
  std::deque<size_t> PieceCache;
  std::deque<size_t> PieceCacheRecent;

  void addToCache(ClangdIndexDataPieceRef Piece);
  void markRecentlyUsed(ClangdIndexDataPieceRef Piece);

  // Look-up the free block table for a free block of a given size.
  RecordPointer getFirstFreeBlock(unsigned Blocksize) const;
  RecordPointer createNewPiece();
  void releasePiece(ClangdIndexDataPieceRef Piece);
  void setFirstFreeBlock(unsigned Blocksize, RecordPointer Block);
  void flushAllPieces();
  static int blockSizeToFreeBlockEntryOffset(unsigned Blocksize);
  std::unique_ptr<FreeBlock> takeFirstFreeBlock(
      unsigned MinimumNeededBlockSize);

public:
  const static unsigned PTR_SIZE = 4;

  const static unsigned DATA_AREA = blockSizeToFreeBlockEntryOffsetConstExpr(
      MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, BLOCK_SIZE_INCREMENT, PTR_SIZE,
      FREE_BLOCK_TABLE_START) + PTR_SIZE;
  const static unsigned MALLOC_AREA_START = ClangdIndexDataPiece::PIECE_SIZE;

  ClangdIndexDataStorage(const std::string &FilePath, unsigned Version);
  virtual ~ClangdIndexDataStorage();

  void readPiece(char* Buf, std::streampos Position);
  void writePiece(char* Buf, std::streampos Position);
  RecordPointer mallocRecord(unsigned Datasize);
  void freeRecord(RecordPointer Offset);
  void flush();
  ClangdIndexDataPieceRef getDataPiece(RecordPointer Rec);
  void putRecPtr(RecordPointer Rec, RecordPointer Value);
  void putInt8(RecordPointer Rec, int8_t);
  int8_t getInt8(RecordPointer Rec);
  void putInt32(RecordPointer Rec, int32_t);
  int32_t getInt32(RecordPointer Rec);
  RecordPointer getRecPtr(RecordPointer Rec);
  void putData(RecordPointer Rec, void *Data, size_t Size);
  void getData(RecordPointer Rec, void *Result, size_t Size);
  unsigned getVersion() { return Version; }
  void startWrite() {
    WriteMode = true;
  }
  void endWrite();

  bool isValid() const { return !FileStream.bad(); }
  bool isInvalid() const { return !isValid(); }
  explicit operator bool() const { return isValid(); }
  explicit operator ClangdIndexDataPieceRef() const { return HeaderDataPiece; }
};

template <class T, class... Args>
static std::unique_ptr<T> getPtrOrNull(ClangdIndexDataStorage &Storage, RecordPointer Offset,
    Args &&... args) {
  RecordPointer Rec = Storage.getRecPtr(Offset);
  if (Rec == 0) {
    return {};
  }
  return llvm::make_unique<T>(Storage, Rec, std::forward<Args>(args)...);
}

// Chances are that we will never have fields at an offset more than a uint8 so
// use we can save a little space.
using OffsetInRecord = uint8_t;

} // namespace clangd
} // namespace clang

#endif
