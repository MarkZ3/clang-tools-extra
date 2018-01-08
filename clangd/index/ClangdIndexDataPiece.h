//===--- ClangdIndexDataPiece.h - Piece of data in index ------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATAPIECE_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATAPIECE_H

#include <memory>

#include "llvm/Support/Error.h"

namespace clang {
namespace clangd {

using RecordPointer = int64_t;

class ClangdIndexDataStorage;

/// A piece of data in the index. See ClangdIndexDataStorage.
class ClangdIndexDataPiece {
public:
  ClangdIndexDataPiece(ClangdIndexDataStorage &Storage, unsigned ID);
  llvm::Error read();
  void clear(RecordPointer Rec, unsigned Length);
  void flush();

  void putInt8(RecordPointer Rec, int8_t Value);
  int8_t getInt8(RecordPointer Rec);
  void putInt16(RecordPointer Rec, int16_t Value);
  int16_t getInt16(RecordPointer Rec);
  void putInt32(RecordPointer Rec, int32_t Value);
  int32_t getInt32(RecordPointer Rec);
  void putRecPtr(RecordPointer Rec, RecordPointer Value);
  RecordPointer getRecPtr(RecordPointer Rec);
  void putRawRecPtr(RecordPointer Rec, RecordPointer Value);
  RecordPointer getRawRecPtr(RecordPointer Rec);
  void putChars(RecordPointer Rec, const char *Chars, unsigned Len);
  void getChars(RecordPointer Rec, char *Result, unsigned Len);
  void putData(RecordPointer Rec, void *Data, size_t Size);
  void getData(RecordPointer Rec, void *Result, size_t Size);

  const static unsigned PIECE_SIZE = 1024 * 4;

  size_t ID;
  // Cached pieces can stay in memory even after being flushed.
  bool InCache;
  // A piece recently added to the cache is "protected".
  bool InCacheRecent;
  // Number of times used, to choose which piece to remove from cache.
  uint16_t UsedTimes;

  // Piece was written or needs to be written to disk
  bool IsDirty;

  // Pieces used or created in write mode and not released from memory until
  // the write is over and pieces are flushed.
  bool CanBeReleased;

private:
  char Buffer[PIECE_SIZE] = {0};
  ClangdIndexDataStorage &Storage;

  unsigned recPtrToOffsetInPiece(RecordPointer Rec);
  void startWrite();
};

using ClangdIndexDataPieceRef = std::shared_ptr<ClangdIndexDataPiece>;

} // namespace clangd
} // namespace clang

#endif
