//===--- GlobalCompilationDatabase.cpp --------------------------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===---------------------------------------------------------------------===//

#include "GlobalCompilationDatabase.h"
#include "Logger.h"
#include "index/ClangdIndex.h"

#include "clang/Tooling/CompilationDatabase.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

namespace clang {
namespace clangd {

tooling::CompileCommand
GlobalCompilationDatabase::getFallbackCommand(PathRef File) const {
  std::vector<std::string> Argv = {"clang"};
  // Clang treats .h files as C by default, resulting in unhelpful diagnostics.
  // Parsing as Objective C++ is friendly to more cases.
  if (llvm::sys::path::extension(File) == ".h")
    Argv.push_back("-xobjective-c++-header");
  Argv.push_back(File);
  return tooling::CompileCommand(llvm::sys::path::parent_path(File),
                                 llvm::sys::path::filename(File),
                                 std::move(Argv),
                                 /*Output=*/"");
}

DirectoryBasedGlobalCompilationDatabase::
    DirectoryBasedGlobalCompilationDatabase(
        llvm::Optional<Path> CompileCommandsDir)
    : CompileCommandsDir(std::move(CompileCommandsDir)) {}

DirectoryBasedGlobalCompilationDatabase::
    ~DirectoryBasedGlobalCompilationDatabase() = default;

llvm::Optional<tooling::CompileCommand> DirectoryBasedGlobalCompilationDatabase::getCompileCommandsUsingIndex(std::unique_ptr<ClangdIndexFile> IndexFile, bool InferMissing) const {

  llvm::Optional<tooling::CompileCommand> Commands;

  class FirstDependentSourceFileVisitor : public ClangdIndexFile::DependentVisitor {
    const DirectoryBasedGlobalCompilationDatabase &GCDB;
    llvm::Optional<tooling::CompileCommand> &Commands;
    bool InferMissing;
  public:
    FirstDependentSourceFileVisitor(const DirectoryBasedGlobalCompilationDatabase &GCDB,
        llvm::Optional<tooling::CompileCommand> &Commands, bool InferMissing) :
          GCDB(GCDB), Commands(Commands), InferMissing(InferMissing) {
    }

    virtual ClangdIndexFile::NodeVisitResult VisitDependent(ClangdIndexFile& IndexFile) {
      auto IncludedBy = IndexFile.getFirstIncludedBy();
      if (!IncludedBy) {
        Commands = GCDB.getCompileCommand(IndexFile.getPath(), InferMissing);
        if (Commands)
          return ClangdIndexFile::NodeVisitResult::ABORT;
      }
      return ClangdIndexFile::NodeVisitResult::CONTINUE;
    }
  };

  FirstDependentSourceFileVisitor V(*this, Commands, InferMissing);
  IndexFile->visitDependentFiles(V);
  return Commands;
}

llvm::Optional<tooling::CompileCommand>
DirectoryBasedGlobalCompilationDatabase::getCompileCommand(PathRef File, bool InferMissing) const {
  if (auto CDB = getCDBForFile(File, InferMissing)) {
    auto Candidates = CDB->getCompileCommands(File);
    if (!Candidates.empty()) {
      addExtraFlags(File, Candidates.front());
      return std::move(Candidates.front());
    }
  } else {
    //TODO: index mutex needs to be locked!
    if (auto LockedIndex = Index.lock()) {
      auto IndexFile = LockedIndex->getFile(File.str());
      if (IndexFile) {
        auto Commands = getCompileCommandsUsingIndex(std::move(IndexFile), InferMissing);
        if (Commands)
          return Commands;
      }
    }
    log("Failed to find compilation database for " + Twine(File));
  }
  return llvm::None;
}

tooling::CompileCommand
DirectoryBasedGlobalCompilationDatabase::getFallbackCommand(
    PathRef File) const {
  auto C = GlobalCompilationDatabase::getFallbackCommand(File);
  addExtraFlags(File, C);
  return C;
}

void DirectoryBasedGlobalCompilationDatabase::setCompileCommandsDir(Path P) {
  std::lock_guard<std::mutex> Lock(Mutex);
  CompileCommandsDir = P;
  CompilationDatabases.clear();
}

void DirectoryBasedGlobalCompilationDatabase::setExtraFlagsForFile(
    PathRef File, std::vector<std::string> ExtraFlags) {
  std::lock_guard<std::mutex> Lock(Mutex);
  ExtraFlagsForFile[File] = std::move(ExtraFlags);
}

void DirectoryBasedGlobalCompilationDatabase::addExtraFlags(
    PathRef File, tooling::CompileCommand &C) const {
  std::lock_guard<std::mutex> Lock(Mutex);

  auto It = ExtraFlagsForFile.find(File);
  if (It == ExtraFlagsForFile.end())
    return;

  auto &Args = C.CommandLine;
  assert(Args.size() >= 2 && "Expected at least [compiler, source file]");
  // The last argument of CommandLine is the name of the input file.
  // Add ExtraFlags before it.
  Args.insert(Args.end() - 1, It->second.begin(), It->second.end());
}

tooling::CompilationDatabase *
DirectoryBasedGlobalCompilationDatabase::getCDBInDirLocked(PathRef Dir, bool InferMissing) const {
  // FIXME(ibiryukov): Invalidate cached compilation databases on changes
  auto CachedIt = CompilationDatabases.find(Dir);
  if (CachedIt != CompilationDatabases.end())
    return InferMissing ? CachedIt->second.first.get() : CachedIt->second.second;
  std::string Error = "";
  auto CDB = tooling::CompilationDatabase::loadFromDirectory(Dir, Error);
  tooling::CompilationDatabase* CDBRawPtr = nullptr;
  if (CDB) {
    CDBRawPtr = CDB.get();
    CDB = tooling::inferMissingCompileCommands(std::move(CDB));
  }
  auto Result = CDB.get();
  CompilationDatabases.insert(std::make_pair(Dir, std::make_pair(std::move(CDB), CDBRawPtr)));
  return Result;
}

tooling::CompilationDatabase *
DirectoryBasedGlobalCompilationDatabase::getCDBForFile(PathRef File, bool InferMissing) const {
  namespace path = llvm::sys::path;
  assert((path::is_absolute(File, path::Style::posix) ||
          path::is_absolute(File, path::Style::windows)) &&
         "path must be absolute");

  std::lock_guard<std::mutex> Lock(Mutex);
  if (CompileCommandsDir)
    return getCDBInDirLocked(*CompileCommandsDir, InferMissing);
  for (auto Path = path::parent_path(File); !Path.empty();
       Path = path::parent_path(Path))
    if (auto CDB = getCDBInDirLocked(Path, InferMissing))
      return CDB;
  return nullptr;
}

CachingCompilationDb::CachingCompilationDb(
    const GlobalCompilationDatabase &InnerCDB)
    : InnerCDB(InnerCDB) {}

llvm::Optional<tooling::CompileCommand>
CachingCompilationDb::getCompileCommand(PathRef File, bool InferMissing) const {
  std::unique_lock<std::mutex> Lock(Mut);
  auto It = Cached.find(File);
  if (It != Cached.end())
    return It->second;

  Lock.unlock();
  llvm::Optional<tooling::CompileCommand> Command =
      InnerCDB.getCompileCommand(File, InferMissing);
  Lock.lock();
  return Cached.try_emplace(File, std::move(Command)).first->getValue();
}

tooling::CompileCommand
CachingCompilationDb::getFallbackCommand(PathRef File) const {
  return InnerCDB.getFallbackCommand(File);
}

void CachingCompilationDb::invalidate(PathRef File) {
  std::unique_lock<std::mutex> Lock(Mut);
  Cached.erase(File);
}

void CachingCompilationDb::clear() {
  std::unique_lock<std::mutex> Lock(Mut);
  Cached.clear();
}

} // namespace clangd
} // namespace clang
