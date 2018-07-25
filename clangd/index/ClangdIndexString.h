#ifndef TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXSTRING_H_
#define TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXSTRING_H_

#include "ClangdIndexDataStorage.h"

#include <string>

namespace clang {
namespace clangd {

class ClangdIndexString {
  ClangdIndexDataStorage &Storage;
  RecordPointer Record;
public:
  ClangdIndexString(ClangdIndexDataStorage &Storage, RecordPointer Rec);
  ClangdIndexString(ClangdIndexDataStorage &Storage, const std::string &Str);
  std::string getString();
  RecordPointer getRecord() const;
  const static unsigned MAX_STRING_SIZE;
};

} // namespace clangd
} // namespace clang

#endif
