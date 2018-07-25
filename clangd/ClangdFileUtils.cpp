#include "ClangdFileUtils.h"

using namespace clang;
using namespace clangd;

using llvm::StringRef;

StringRef SourceExtensions[] = {".cpp", ".c", ".cc", ".cxx",
                                ".c++", ".m", ".mm"};
StringRef HeaderExtensions[] = {".h", ".hh", ".hpp", ".hxx", ".inc"};

llvm::ArrayRef<StringRef> getSourceExtensions() {
  return llvm::ArrayRef<StringRef>(SourceExtensions);
}
llvm::ArrayRef<StringRef> getHeaderExtensions() {
  return llvm::ArrayRef<StringRef>(HeaderExtensions);
}

bool isSourceFilePath(PathRef Path) {
  StringRef PathExt = llvm::sys::path::extension(Path);

  auto SourceIter =
      std::find_if(std::begin(SourceExtensions), std::end(SourceExtensions),
                   [&PathExt](PathRef SourceExt) {
                     return SourceExt.equals_lower(PathExt);
                   });
  return SourceIter != std::end(SourceExtensions);
}

bool isHeaderFilePath(StringRef Path) {
  StringRef PathExt = llvm::sys::path::extension(Path);

  auto HeaderIter =
      std::find_if(std::begin(HeaderExtensions), std::end(HeaderExtensions),
                   [&PathExt](PathRef HeaderExt) {
                     return HeaderExt.equals_lower(PathExt);
                   });

  return HeaderIter != std::end(HeaderExtensions);
}
