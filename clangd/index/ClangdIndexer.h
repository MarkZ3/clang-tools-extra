#ifndef TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATABUILDER_H_
#define TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATABUILDER_H_


#include "Path.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/FileSystem.h"

using llvm::StringRef;

namespace clang {
namespace clangd {

class ClangdIndexDataProvider;

class ClangdIndexer {

private:
  std::vector<Path> ExclusionList;
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
  virtual void printStats() = 0;


  virtual std::vector<Path> getExclusionList() = 0;
  virtual void setExclusionList(std::vector<Path> FilesToBeExcluded) = 0;
  virtual ~ClangdIndexer() = default;
};

} /* namespace clangd */
} /* namespace clang */

#endif /* TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATABUILDER_H_ */
