#ifndef TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATABUILDER_H_
#define TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATABUILDER_H_

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/FileSystem.h"

using llvm::StringRef;

namespace clang {
namespace clangd {

class ClangdIndexDataProvider;

struct ClangdIndexerOptions {
  bool IncludeCDBFilesOnly = true;
};

class ClangdIndexer {
public:
  enum class FileChangeType {
    Created = 1,
    Changed = 2,
    Deleted = 3
  };

  struct FileEvent {
    std::string Path;
    FileChangeType type;
  };

  virtual void onFileEvent(FileEvent Event) {}
  virtual void indexRoot() = 0;
  virtual void reindex() = 0;
  virtual void printStats() {}

  virtual ~ClangdIndexer() = default;
};

} /* namespace clangd */
} /* namespace clang */

#endif /* TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATABUILDER_H_ */
