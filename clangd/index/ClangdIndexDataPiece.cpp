//===--- ClangdIndexDataPiece.cpp - Piece of data in index ----*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#include "ClangdIndexDataPiece.h"

#include "ClangdIndexDataStorage.h"

#include <cassert>
#include <cstring>

namespace clang {
namespace clangd {

const unsigned ClangdIndexDataPiece::PIECE_SIZE;

ClangdIndexDataPiece::ClangdIndexDataPiece(ClangdIndexDataStorage &Storage,
    unsigned ID) :
    ID(ID), InCache(false), InCacheRecent(false), UsedTimes(0u), IsDirty(false), CanBeReleased(true), Storage(
        Storage) {
}

llvm::Error ClangdIndexDataPiece::read() {
  Storage.readPiece(Buffer, ID * PIECE_SIZE);
}

void ClangdIndexDataPiece::clear(RecordPointer Rec, unsigned Length) {
  startWrite();
  memset(&Buffer[recPtrToOffsetInPiece(Rec)], 0, Length);
}

void ClangdIndexDataPiece::flush() {
  Storage.writePiece(Buffer, ID * PIECE_SIZE);
  IsDirty = false;
}

void ClangdIndexDataPiece::startWrite() {
  assert(!CanBeReleased);
  IsDirty = true;
}

void ClangdIndexDataPiece::putInt16(RecordPointer Rec, int16_t Value) {
  startWrite();
  *(reinterpret_cast<int16_t *>(&Buffer[recPtrToOffsetInPiece(Rec)])) = Value;
}

int16_t ClangdIndexDataPiece::getInt16(RecordPointer Rec) {
  return *reinterpret_cast<int16_t *>(&Buffer[recPtrToOffsetInPiece(Rec)]);
}

// See ClangdIndexDataStorage::MAX_STORAGE_ADDRESS, for how and why pointers are
// compressed to 32 bits.
namespace {
int32_t compressRecPtr(RecordPointer Value) {
  // Verify proper alignment of pointer. We only allocate in increments of
  // BLOCK_SIZE_INCREMENT so those bits must be cleared.
  assert((Value & (ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT - 1)) == 0);
  return (int32_t) (Value >> ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT_BITS);
}

RecordPointer uncompressRecPtr(int32_t Value) {
  // We use the int32 bits as an unsigned
  RecordPointer Address = Value & 0xFFFFFFFF;
  return Address << ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT_BITS;
}
}

void ClangdIndexDataPiece::putInt8(RecordPointer Rec, int8_t Value) {
  startWrite();
  *(reinterpret_cast<int8_t *>(&Buffer[recPtrToOffsetInPiece(Rec)])) = Value;
}

int8_t ClangdIndexDataPiece::getInt8(RecordPointer Rec) {
  return *reinterpret_cast<int8_t *>(&Buffer[recPtrToOffsetInPiece(Rec)]);
}

void ClangdIndexDataPiece::putInt32(RecordPointer Rec, int32_t Value) {
  startWrite();
  *(reinterpret_cast<int32_t *>(&Buffer[recPtrToOffsetInPiece(Rec)])) = Value;
}

void ClangdIndexDataPiece::putRecPtr(RecordPointer Rec, RecordPointer Value) {
  assert(Value < ClangdIndexDataStorage::MAX_STORAGE_ADDRESS);

  startWrite();
  int32_t CompressedRecPtr = Value == 0 ? 0 :
      compressRecPtr(Value - ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
  ClangdIndexDataPiece::putInt32(Rec, CompressedRecPtr);
}

void ClangdIndexDataPiece::putChars(RecordPointer Rec, const char *Chars,
    unsigned len) {
  startWrite();
  strncpy(&Buffer[recPtrToOffsetInPiece(Rec)], Chars, len);
}

unsigned ClangdIndexDataPiece::recPtrToOffsetInPiece(RecordPointer Rec) {
  const unsigned OFFSET_IN_PIECE_MASK = ClangdIndexDataPiece::PIECE_SIZE - 1;
  return (unsigned) (Rec & OFFSET_IN_PIECE_MASK);
}

void ClangdIndexDataPiece::putRawRecPtr(RecordPointer Rec,
    RecordPointer Value) {
  assert(Value < ClangdIndexDataStorage::MAX_STORAGE_ADDRESS);

  startWrite();
  putInt32(Rec, compressRecPtr(Value));
}

int32_t ClangdIndexDataPiece::getInt32(RecordPointer Rec) {
  return *reinterpret_cast<int32_t *>(&Buffer[recPtrToOffsetInPiece(Rec)]);
}

void ClangdIndexDataPiece::getChars(RecordPointer Rec, char *Result,
    unsigned len) {
  strncpy(Result, &Buffer[recPtrToOffsetInPiece(Rec)], len);
}

RecordPointer ClangdIndexDataPiece::getRecPtr(RecordPointer Rec) {
  RecordPointer RawRecPtr = getRawRecPtr(Rec);
  return RawRecPtr == 0 ? 0 :
      (RawRecPtr + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
}

RecordPointer ClangdIndexDataPiece::getRawRecPtr(RecordPointer Rec) {
  return uncompressRecPtr(getInt32(Rec));
}

void ClangdIndexDataPiece::putData(RecordPointer Rec, void *Data,
    size_t Size) {
  startWrite();
  memcpy(&Buffer[recPtrToOffsetInPiece(Rec)], Data, Size);
}

void ClangdIndexDataPiece::getData(RecordPointer Rec, void *Result,
    size_t Size) {
  memcpy(Result, &Buffer[recPtrToOffsetInPiece(Rec)], Size);
}

} // namespace clangd
} // namespace clang
