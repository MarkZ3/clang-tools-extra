#include "ClangdIndexString.h"

#include "ClangdIndexDataStorage.h"

#include <cassert>

using namespace clang;
using namespace clangd;

const static unsigned LENGTH_OFFSET = 0;
const static unsigned CHARS_OFFSET = 4;

const unsigned ClangdIndexString::MAX_STRING_SIZE = ClangdIndexDataStorage::MAX_MALLOC_SIZE - CHARS_OFFSET;

ClangdIndexString::ClangdIndexString(ClangdIndexDataStorage &Storage,
    RecordPointer Rec) :
    Storage(Storage), Record(Rec) {
}

ClangdIndexString::ClangdIndexString(ClangdIndexDataStorage &Storage,
    const std::string &Str) :
    Storage(Storage) {
  unsigned Length = Str.length();
  assert(Length <= ClangdIndexDataStorage::MAX_MALLOC_SIZE - CHARS_OFFSET && "Long strings are not supported yet.");
  Record = Storage.mallocRecord(CHARS_OFFSET + Length);
  auto Piece = Storage.getDataPiece(Record);
  Piece->putInt32(Record + LENGTH_OFFSET, Length);
  Piece->putChars(Record + CHARS_OFFSET, Str.c_str(), Length);
}

std::string ClangdIndexString::getString() {
  auto Piece = Storage.getDataPiece(Record);
  auto Length = Piece->getInt32(Record + LENGTH_OFFSET);
  std::vector<char> Str(Length + 1);
  Piece->getChars(Record + CHARS_OFFSET, Str.data(), Length);
  Str[Length] = '\0';
  return Str.data();
}

RecordPointer ClangdIndexString::getRecord() const {
  return Record;
}

