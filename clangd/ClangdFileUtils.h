#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANGDUNITUTILS_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANGDUNITUTILS_H

#include "Path.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Path.h"

using namespace clang;
using namespace clangd;

using llvm::StringRef;

llvm::ArrayRef<StringRef> getSourceExtensions();
llvm::ArrayRef<StringRef> getHeaderExtensions();

bool isSourceFilePath(PathRef Path);
bool isHeaderFilePath(StringRef Path);

#endif
