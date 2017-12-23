#ifndef TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXERIMPL_H_
#define TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXERIMPL_H_

#include "ClangdIndexer.h"
#include "../Path.h"
#include "ClangdIndexDataProvider.h"

#include "../GlobalCompilationDatabase.h"

namespace clang {
namespace clangd {

class ClangdIndex;

class ClangdIndexerImpl: public ClangdIndexer, public ClangdIndexDataProvider {
  std::string RootPath;
  GlobalCompilationDatabase &CDB;
  std::vector<Path> ExclusionList;
  std::shared_ptr<ClangdIndex> Index;
  bool IsFromScratch = false;

public:
  ClangdIndexerImpl(std::string RootPath, GlobalCompilationDatabase &CDB,
                    std::vector<Path> ExclusionList);
public:
  ClangdIndexerImpl(std::string RootPath, GlobalCompilationDatabase &CDB);
  void onFileEvent(FileEvent Event) override;
  void indexRoot() override;
  void reindex() override;
  void printStats() override;
  void foreachSymbols(StringRef Query,
      llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) override;
  void foreachSymbols(const USR &Usr,
      llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) override;

  void dumpIncludedBy(StringRef File) override;
  void dumpInclusions(StringRef File) override;
  std::vector<Path> getExclusionList() override { return ExclusionList; };

  void setExclusionList(std::vector<Path> FilesToBeExcluded) override {
    ExclusionList.clear();
    for (auto CurrentPath : FilesToBeExcluded)
      ExclusionList.push_back(CurrentPath);
  };

private:
  void indexFile (StringRef File);
  void indexFiles(const std::vector<std::string>& FilesToIndex);
};

} /* namespace clangd */
} /* namespace clang */

#endif /* TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXERIMPL_H_ */
