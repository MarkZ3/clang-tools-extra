//===--- ClangdIndexDataStorage.cpp - Index storage code ------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#include "ClangdIndexDataStorage.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/raw_ostream.h"

namespace clang {
namespace clangd {

const unsigned ClangdIndexDataStorage::MIN_BLOCK_SIZE;
const unsigned ClangdIndexDataStorage::MAX_BLOCK_SIZE;
const unsigned ClangdIndexDataStorage::MALLOC_AREA_START;

//TODO: Cache should eventually be configurable.
const unsigned DEFAULT_CACHE_SIZE = 64 * 1024 * 1024;
const unsigned DEFAULT_CACHE_SIZE_PIECES = DEFAULT_CACHE_SIZE
    / ClangdIndexDataPiece::PIECE_SIZE;
const unsigned DEFAULT_CACHE_RECENT_SIZE_PIECES = DEFAULT_CACHE_SIZE_PIECES / 3;

ClangdIndexDataStorage::ClangdIndexDataStorage(const std::string &FilePath,
    unsigned Version) :
    FileStream(FilePath), WriteMode(false), Version(Version) {
  if (!FileStream.is_open()) {
    FileStream.clear();
    // Create the file
    FileStream.open(FilePath, std::ios::out);
    FileStream.close();
    FileStream.open(FilePath);
  }

  if (!FileStream.is_open()) {
    llvm::errs() << "Could not open index file" << "\n";
  }

  HeaderDataPiece = std::make_shared<ClangdIndexDataPiece>(*this, 0);
  // Header should not be released, it's always in "write mode".
  HeaderDataPiece->CanBeReleased = false;

  FileStream.seekg(0, std::ios::end);

  std::streampos FileSize = FileStream.tellg();
  if (FileSize >= ClangdIndexDataPiece::PIECE_SIZE) {
    size_t NbPiecesInFile = FileSize / ClangdIndexDataPiece::PIECE_SIZE;
    HeaderDataPiece->read();
    Version = HeaderDataPiece->getInt32(VERSION_OFFSET);
    Pieces.resize(NbPiecesInFile);
  } else {
    Pieces.resize(1);
    // Make sure we write something to disk the first time it gets created even
    // though it can just be the version number.
    HeaderDataPiece->IsDirty = true;
  }
}

void ClangdIndexDataStorage::writePiece(char *Buffer, std::streampos Position) {
  FileStream.seekp(Position, std::ios::beg);
  FileStream.write(Buffer, ClangdIndexDataPiece::PIECE_SIZE);
}

ClangdIndexDataStorage::~ClangdIndexDataStorage() {
  flush();
  FileStream.close();
}

std::unique_ptr<ClangdIndexDataStorage::FreeBlock>
ClangdIndexDataStorage::takeFirstFreeBlock(
    unsigned MinimumNeededBlockSize) {
  for (unsigned CurBlockSize = MinimumNeededBlockSize;
      CurBlockSize <= MAX_BLOCK_SIZE; CurBlockSize += BLOCK_SIZE_INCREMENT) {
    RecordPointer FreeBlockOffset = getFirstFreeBlock(CurBlockSize);
    if (FreeBlockOffset != 0) {
      auto FB = llvm::make_unique<FreeBlock>(*this, FreeBlockOffset);
      FB->Remove();
      return FB;
    }
  }
  return {};
}

ClangdIndexDataStorage::DataBlock::DataBlock(ClangdIndexDataStorage& Storage,
    RecordPointer Rec) :
    Storage(Storage), Record(Rec) {
}

ClangdIndexDataStorage::DataBlock::DataBlock(ClangdIndexDataStorage& Storage,
    unsigned RequestedSize) : Storage(Storage) {
  // The block has to fit in an increment of BLOCK_SIZE_INCREMENT
  unsigned MinimumNeededBlockSize = (RequestedSize + BLOCK_HEADER_SIZE
      + BLOCK_SIZE_INCREMENT - 1) / BLOCK_SIZE_INCREMENT * BLOCK_SIZE_INCREMENT;
  MinimumNeededBlockSize = std::max(MIN_BLOCK_SIZE, MinimumNeededBlockSize);

  // Find or create a free block that suits the minimum size
  auto FB = Storage.takeFirstFreeBlock(MinimumNeededBlockSize);
  if (!FB) {
    // No free block, create a brand new block
    FB = llvm::make_unique<FreeBlock>(Storage, Storage.createNewPiece(),
        MAX_BLOCK_SIZE, false);
  }

  FB->convertIntoDataBlock(MinimumNeededBlockSize);
  Record = FB->Record;
}

void ClangdIndexDataStorage::FreeBlock::convertIntoDataBlock(
    unsigned RequestedSize) {
  // The unused left over can become a free block, if big enough
  int16_t AllocatedSize = getSize();
  unsigned UnusedSize = AllocatedSize - RequestedSize;
  if (UnusedSize >= MIN_BLOCK_SIZE) {
    FreeBlock(Storage, Record + RequestedSize, UnusedSize, true);
    AllocatedSize = RequestedSize;
  }

  // Data blocks have negative size to indicate
  // they are used and not free blocks
  Storage.getDataPiece(Record)->putInt16(Record + DATA_BLOCK_SIZE_OFFSET,
      -AllocatedSize);
}

RecordPointer ClangdIndexDataStorage::DataBlock::getUserDataRecPointer() const {
  // User data starts right after the size
  return Record + BLOCK_HEADER_SIZE;
}

int16_t ClangdIndexDataStorage::DataBlock::getSize() {
  // Data blocks have negative size to indicate they are not free blocks
  return -Storage.getDataPiece(Record)->getInt16(
      Record + DATA_BLOCK_SIZE_OFFSET);
}

void ClangdIndexDataStorage::DataBlock::free() {
  int16_t Size = getSize();
  assert (Size >= 0);
  FreeBlock(Storage, Record, Size, true);
}

RecordPointer ClangdIndexDataStorage::mallocRecord(unsigned Size) {
  assert(Size <= MAX_MALLOC_SIZE);

  DataBlock Block(*this, Size);
  return Block.getUserDataRecPointer();
}

void ClangdIndexDataStorage::freeRecord(RecordPointer Rec) {
  DataBlock Block (*this, Rec - BLOCK_HEADER_SIZE);
  Block.free();
}

int ClangdIndexDataStorage::blockSizeToFreeBlockEntryOffset(
    unsigned Blocksize) {
  return blockSizeToFreeBlockEntryOffsetConstExpr(Blocksize, MIN_BLOCK_SIZE,
      BLOCK_SIZE_INCREMENT, PTR_SIZE, FREE_BLOCK_TABLE_START);
}

void ClangdIndexDataStorage::setFirstFreeBlock(unsigned Blocksize,
    RecordPointer Block) {
  HeaderDataPiece->putRawRecPtr(blockSizeToFreeBlockEntryOffset(Blocksize),
      Block);
}

ClangdIndexDataStorage::FreeBlock::FreeBlock(ClangdIndexDataStorage& Storage,
    RecordPointer Rec) :
    Storage(Storage), Record(Rec) {
}

ClangdIndexDataStorage::FreeBlock::FreeBlock(ClangdIndexDataStorage& Storage,
    RecordPointer Rec, int Blocksize, bool AddToFreeBlockTable) :
    Storage(Storage), Record(Rec) {
  auto Piece = Storage.getDataPiece(Rec);
  Piece->putInt16(Rec + FREE_BLOCK_SIZE_OFFSET, Blocksize);
  // We don't need to add it to the table in cases where we know that the
  // FreeBlock will be converted to a data block right away.
  if (!AddToFreeBlockTable) {
    return;
  }

  RecordPointer CurrentFirstFreeBlock = Storage.getFirstFreeBlock(Blocksize);
  Storage.setFirstFreeBlock(Blocksize, Rec);
  Piece->putRawRecPtr(Rec + FREE_BLOCK_NEXT_OFFSET, CurrentFirstFreeBlock);
}

int16_t ClangdIndexDataStorage::FreeBlock::getSize() {
  return Storage.getDataPiece(Record)->getInt16(
      Record + FREE_BLOCK_SIZE_OFFSET);
}

void ClangdIndexDataStorage::FreeBlock::Remove() {
  // Remove from FreeBlock table for this specific size
  auto Piece = Storage.getDataPiece(Record);
  int16_t Size = getSize();
  RecordPointer NextFreeBlock = Piece->getRawRecPtr(
      Record + FREE_BLOCK_NEXT_OFFSET);
  Storage.setFirstFreeBlock(Size, NextFreeBlock);
  // Clear so that it can be safely used as a data block
  Piece->clear(Record + BLOCK_HEADER_SIZE, Size - BLOCK_HEADER_SIZE);
}

void ClangdIndexDataStorage::putRecPtr(RecordPointer Rec, RecordPointer Value) {
  assert(WriteMode);
  getDataPiece(Rec)->putRecPtr(Rec, Value);
}

void ClangdIndexDataStorage::putInt8(RecordPointer Rec, int8_t Value) {
  assert(WriteMode);
  getDataPiece(Rec)->putInt8(Rec, Value);
}

int8_t ClangdIndexDataStorage::getInt8(RecordPointer Rec) {
  return getDataPiece(Rec)->getInt8(Rec);
}

void ClangdIndexDataStorage::putInt32(RecordPointer Rec, int Value) {
  assert(WriteMode);
  getDataPiece(Rec)->putInt32(Rec, Value);
}

int32_t ClangdIndexDataStorage::getInt32(RecordPointer Rec) {
  return getDataPiece(Rec)->getInt32(Rec);
}

RecordPointer ClangdIndexDataStorage::getRecPtr(RecordPointer Rec) {
  RecordPointer RecPtr = getDataPiece(Rec)->getRecPtr(Rec);
  assert (RecPtr == 0 || RecPtr >= ClangdIndexDataStorage::DATA_AREA);
  return RecPtr;
}

void ClangdIndexDataStorage::putData(RecordPointer Rec, void *Data, size_t Size) {
  getDataPiece(Rec)->putData(Rec, Data, Size);
}

void ClangdIndexDataStorage::getData(RecordPointer Rec, void *Data, size_t Size) {
  getDataPiece(Rec)->getData(Rec, Data, Size);
}

RecordPointer ClangdIndexDataStorage::getFirstFreeBlock(
    unsigned Blocksize) const {
  return HeaderDataPiece->getRawRecPtr(
      blockSizeToFreeBlockEntryOffset(Blocksize));
}

ClangdIndexDataPieceRef ClangdIndexDataStorage::getDataPiece(
    RecordPointer Rec) {
  size_t PieceID = Rec / ClangdIndexDataPiece::PIECE_SIZE;
  // "Pieces" should be big enough to contain entries (null or otherwise) for
  // all previously created pieces
  assert(PieceID < MAX_PIECE_ID && PieceID < Pieces.size()
          && "Invalid piece ID. Reading out of the bounds of the index.");
  if (PieceID == 0) {
    return HeaderDataPiece;
  }

  auto Piece = Pieces[PieceID];
  if (Piece) {
    if (Piece->InCache)
      markRecentlyUsed(Piece);
  } else {
    Piece = std::make_shared<ClangdIndexDataPiece>(*this, PieceID);
    Pieces[PieceID] = Piece;
    Piece->read();
    addToCache(Piece);
  }
  Piece->CanBeReleased = Piece->CanBeReleased && !WriteMode;

  return Piece;
}

void ClangdIndexDataStorage::readPiece(char* Buf, std::streampos Position) {
  FileStream.seekg(Position, std::ios::beg);
  FileStream.read(Buf, ClangdIndexDataPiece::PIECE_SIZE);
}

RecordPointer ClangdIndexDataStorage::createNewPiece() {
  assert (Pieces.size() < MAX_PIECE_ID && "Index cannot contain more data.");
  assert(WriteMode && "Index not in write mode");
  size_t PieceID = Pieces.size();
  auto NewPiece = std::make_shared<ClangdIndexDataPiece>(*this, PieceID);
  NewPiece->IsDirty = true;
  Pieces.push_back(NewPiece);
  // It's a new piece that we're about to write to it so we cannot allow
  // releasing it.
  NewPiece->CanBeReleased = false;
  addToCache(NewPiece);
  return PieceID * ClangdIndexDataPiece::PIECE_SIZE;
}

void ClangdIndexDataStorage::releasePiece(ClangdIndexDataPieceRef Piece) {
  if (Piece->CanBeReleased) {
    Pieces[Piece->ID].reset();
  }
}

void ClangdIndexDataStorage::endWrite() {
  if (!WriteMode) {
    return;
  }

  flushAllPieces();
  WriteMode = false;
}

void ClangdIndexDataStorage::flush() {
  if (WriteMode) {
    endWrite();
    startWrite();
    return;
  }

  flushAllPieces();
}

void ClangdIndexDataStorage::flushAllPieces() {
  HeaderDataPiece->putInt32(VERSION_OFFSET, 0);
  for (auto Piece : Pieces) {
    if (!Piece) {
      continue;
    }

    // A cached, dirty piece is not supposed to be releasable
    assert(!(Piece->InCache && Piece->IsDirty && Piece->CanBeReleased));

    if (Piece->IsDirty) {
      Piece->flush();
    }
    Piece->CanBeReleased = true;
    if (!Piece->InCache) {
      Pieces[Piece->ID].reset();
    }
  }

  HeaderDataPiece->putInt32(VERSION_OFFSET, Version);
  HeaderDataPiece->flush();
}

void ClangdIndexDataStorage::addToCache(ClangdIndexDataPieceRef Piece) {
  assert (!Piece->InCache);
  if (DEFAULT_CACHE_SIZE_PIECES == PieceCache.size()) {
    uint16_t LowestUsedTimes = UINT16_MAX;
    auto PieceIt = PieceCache.begin();
    auto LowestID = PieceIt;
    for (; PieceIt != PieceCache.end(); ++PieceIt) {
      uint16_t UsedTimes = Pieces[*PieceIt]->UsedTimes;
      if (!Pieces[*PieceIt]->InCacheRecent && UsedTimes < LowestUsedTimes) {
        LowestUsedTimes = UsedTimes;
        LowestID = PieceIt;
      }
    }

    auto ReleasedPiece = Pieces[*LowestID];
    // We should be able to find a non-recent piece.
    static_assert(DEFAULT_CACHE_SIZE_PIECES > DEFAULT_CACHE_RECENT_SIZE_PIECES, "Cache for recent pieces must be bigger than total cache");
    assert(!ReleasedPiece->InCacheRecent);
    releasePiece(ReleasedPiece);
    PieceCache.erase(LowestID);
    ReleasedPiece->InCache = false;
  }
  PieceCache.push_back(Piece->ID);
  Piece->InCache = true;

  // Mitigate pieces removed from cache right away because not used enough yet.
  if (DEFAULT_CACHE_RECENT_SIZE_PIECES == PieceCacheRecent.size()) {
    auto NotSoRecentPiece = Pieces[PieceCacheRecent.front()];
    PieceCacheRecent.pop_front();
    NotSoRecentPiece->InCacheRecent = false;
  }
  PieceCacheRecent.push_back(Piece->ID);
  Piece->InCacheRecent = true;
}

void ClangdIndexDataStorage::markRecentlyUsed(ClangdIndexDataPieceRef Piece) {
  assert (Piece->InCache);
  // It's OK if this wraps-around, it will just mean that once in a while, a
  // highly used piece will get removed from the cache wrongly.
  Piece->UsedTimes++;
}

} // namespace clangd
} // namespace clang
