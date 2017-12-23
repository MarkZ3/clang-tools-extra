//===-- ClangdTests.cpp - Clangd unit tests ---------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "ClangdLSPServer.h"
#include "ClangdServer.h"
#include "Context.h"
#include "TestFS.h"
#include "index/ClangdIndexString.h"
#include "clang/Config/config.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Regex.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace clang {
namespace clangd {
namespace {

// Don't wait for async ops in clangd test more than that to avoid blocking
// indefinitely in case of bugs.
static const std::chrono::seconds DefaultFutureTimeout =
    std::chrono::seconds(10);

static bool diagsContainErrors(ArrayRef<DiagWithFixIts> Diagnostics) {
  for (const auto &DiagAndFixIts : Diagnostics) {
    // FIXME: severities returned by clangd should have a descriptive
    // diagnostic severity enum
    const int ErrorSeverity = 1;
    if (DiagAndFixIts.Diag.severity == ErrorSeverity)
      return true;
  }
  return false;
}

class ErrorCheckingDiagConsumer : public DiagnosticsConsumer {
public:
  void
  onDiagnosticsReady(PathRef File,
                     Tagged<std::vector<DiagWithFixIts>> Diagnostics) override {
    bool HadError = diagsContainErrors(Diagnostics.Value);

    std::lock_guard<std::mutex> Lock(Mutex);
    HadErrorInLastDiags = HadError;
    LastVFSTag = Diagnostics.Tag;
  }

  bool hadErrorInLastDiags() {
    std::lock_guard<std::mutex> Lock(Mutex);
    return HadErrorInLastDiags;
  }

  VFSTag lastVFSTag() { return LastVFSTag; }

private:
  std::mutex Mutex;
  bool HadErrorInLastDiags = false;
  VFSTag LastVFSTag = VFSTag();
};

class ConstantFSProvider : public FileSystemProvider {
public:
  ConstantFSProvider(IntrusiveRefCntPtr<vfs::FileSystem> FS,
                     VFSTag Tag = VFSTag())
      : FS(std::move(FS)), Tag(std::move(Tag)) {}

  Tagged<IntrusiveRefCntPtr<vfs::FileSystem>>
  getTaggedFileSystem(PathRef File) override {
    return make_tagged(FS, Tag);
  }

private:
  IntrusiveRefCntPtr<vfs::FileSystem> FS;
  VFSTag Tag;
};

/// Replaces all patterns of the form 0x123abc with spaces
std::string replacePtrsInDump(std::string const &Dump) {
  llvm::Regex RE("0x[0-9a-fA-F]+");
  llvm::SmallVector<StringRef, 1> Matches;
  llvm::StringRef Pending = Dump;

  std::string Result;
  while (RE.match(Pending, &Matches)) {
    assert(Matches.size() == 1 && "Exactly one match expected");
    auto MatchPos = Matches[0].data() - Pending.data();

    Result += Pending.take_front(MatchPos);
    Pending = Pending.drop_front(MatchPos + Matches[0].size());
  }
  Result += Pending;

  return Result;
}

std::string dumpASTWithoutMemoryLocs(ClangdServer &Server, PathRef File) {
  auto DumpWithMemLocs = Server.dumpAST(File);
  return replacePtrsInDump(DumpWithMemLocs);
}

} // namespace

//TODO: Figure out why this doesn't work on mac
#ifndef __APPLE__
class ClangdVFSTest : public ::testing::Test {
protected:
  std::string parseSourceAndDumpAST(
      PathRef SourceFileRelPath, StringRef SourceContents,
      std::vector<std::pair<PathRef, StringRef>> ExtraFiles = {},
      bool ExpectErrors = false) {
    MockFSProvider FS;
    ErrorCheckingDiagConsumer DiagConsumer;
    MockCompilationDatabase CDB;
    ClangdServer Server(CDB, DiagConsumer, FS, getDefaultAsyncThreadsCount(),
                        /*StorePreamblesInMemory=*/true);
    for (const auto &FileWithContents : ExtraFiles)
      FS.Files[getVirtualTestFilePath(FileWithContents.first)] =
          FileWithContents.second;

    auto SourceFilename = getVirtualTestFilePath(SourceFileRelPath);

    FS.ExpectedFile = SourceFilename;

    // Have to sync reparses because requests are processed on the calling
    // thread.
    auto AddDocFuture =
        Server.addDocument(Context::empty(), SourceFilename, SourceContents);

    auto Result = dumpASTWithoutMemoryLocs(Server, SourceFilename);

    // Wait for reparse to finish before checking for errors.
    EXPECT_EQ(AddDocFuture.wait_for(DefaultFutureTimeout),
              std::future_status::ready);
    EXPECT_EQ(ExpectErrors, DiagConsumer.hadErrorInLastDiags());
    return Result;
  }
};

TEST_F(ClangdVFSTest, Parse) {
  // FIXME: figure out a stable format for AST dumps, so that we can check the
  // output of the dump itself is equal to the expected one, not just that it's
  // different.
  auto Empty = parseSourceAndDumpAST("foo.cpp", "", {});
  auto OneDecl = parseSourceAndDumpAST("foo.cpp", "int a;", {});
  auto SomeDecls = parseSourceAndDumpAST("foo.cpp", "int a; int b; int c;", {});
  EXPECT_NE(Empty, OneDecl);
  EXPECT_NE(Empty, SomeDecls);
  EXPECT_NE(SomeDecls, OneDecl);

  auto Empty2 = parseSourceAndDumpAST("foo.cpp", "");
  auto OneDecl2 = parseSourceAndDumpAST("foo.cpp", "int a;");
  auto SomeDecls2 = parseSourceAndDumpAST("foo.cpp", "int a; int b; int c;");
  EXPECT_EQ(Empty, Empty2);
  EXPECT_EQ(OneDecl, OneDecl2);
  EXPECT_EQ(SomeDecls, SomeDecls2);
}

TEST_F(ClangdVFSTest, ParseWithHeader) {
  parseSourceAndDumpAST("foo.cpp", "#include \"foo.h\"", {},
                        /*ExpectErrors=*/true);
  parseSourceAndDumpAST("foo.cpp", "#include \"foo.h\"", {{"foo.h", ""}},
                        /*ExpectErrors=*/false);

  const auto SourceContents = R"cpp(
#include "foo.h"
int b = a;
)cpp";
  parseSourceAndDumpAST("foo.cpp", SourceContents, {{"foo.h", ""}},
                        /*ExpectErrors=*/true);
  parseSourceAndDumpAST("foo.cpp", SourceContents, {{"foo.h", "int a;"}},
                        /*ExpectErrors=*/false);
}

TEST_F(ClangdVFSTest, Reparse) {
  MockFSProvider FS;
  ErrorCheckingDiagConsumer DiagConsumer;
  MockCompilationDatabase CDB;
  ClangdServer Server(CDB, DiagConsumer, FS, getDefaultAsyncThreadsCount(),
                      /*StorePreamblesInMemory=*/true);

  const auto SourceContents = R"cpp(
#include "foo.h"
int b = a;
)cpp";

  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  auto FooH = getVirtualTestFilePath("foo.h");

  FS.Files[FooH] = "int a;";
  FS.Files[FooCpp] = SourceContents;
  FS.ExpectedFile = FooCpp;

  // To sync reparses before checking for errors.
  std::future<Context> ParseFuture;

  ParseFuture = Server.addDocument(Context::empty(), FooCpp, SourceContents);
  auto DumpParse1 = dumpASTWithoutMemoryLocs(Server, FooCpp);
  ASSERT_EQ(ParseFuture.wait_for(DefaultFutureTimeout),
            std::future_status::ready);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());

  ParseFuture = Server.addDocument(Context::empty(), FooCpp, "");
  auto DumpParseEmpty = dumpASTWithoutMemoryLocs(Server, FooCpp);
  ASSERT_EQ(ParseFuture.wait_for(DefaultFutureTimeout),
            std::future_status::ready);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());

  ParseFuture = Server.addDocument(Context::empty(), FooCpp, SourceContents);
  auto DumpParse2 = dumpASTWithoutMemoryLocs(Server, FooCpp);
  ASSERT_EQ(ParseFuture.wait_for(DefaultFutureTimeout),
            std::future_status::ready);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());

  EXPECT_EQ(DumpParse1, DumpParse2);
  EXPECT_NE(DumpParse1, DumpParseEmpty);
}

TEST_F(ClangdVFSTest, ReparseOnHeaderChange) {
  MockFSProvider FS;
  ErrorCheckingDiagConsumer DiagConsumer;
  MockCompilationDatabase CDB;

  ClangdServer Server(CDB, DiagConsumer, FS, getDefaultAsyncThreadsCount(),
                      /*StorePreamblesInMemory=*/true);

  const auto SourceContents = R"cpp(
#include "foo.h"
int b = a;
)cpp";

  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  auto FooH = getVirtualTestFilePath("foo.h");

  FS.Files[FooH] = "int a;";
  FS.Files[FooCpp] = SourceContents;
  FS.ExpectedFile = FooCpp;

  // To sync reparses before checking for errors.
  std::future<Context> ParseFuture;

  ParseFuture = Server.addDocument(Context::empty(), FooCpp, SourceContents);
  auto DumpParse1 = dumpASTWithoutMemoryLocs(Server, FooCpp);
  ASSERT_EQ(ParseFuture.wait_for(DefaultFutureTimeout),
            std::future_status::ready);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());

  FS.Files[FooH] = "";
  ParseFuture = Server.forceReparse(Context::empty(), FooCpp);
  auto DumpParseDifferent = dumpASTWithoutMemoryLocs(Server, FooCpp);
  ASSERT_EQ(ParseFuture.wait_for(DefaultFutureTimeout),
            std::future_status::ready);
  EXPECT_TRUE(DiagConsumer.hadErrorInLastDiags());

  FS.Files[FooH] = "int a;";
  ParseFuture = Server.forceReparse(Context::empty(), FooCpp);
  auto DumpParse2 = dumpASTWithoutMemoryLocs(Server, FooCpp);
  EXPECT_EQ(ParseFuture.wait_for(DefaultFutureTimeout),
            std::future_status::ready);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());

  EXPECT_EQ(DumpParse1, DumpParse2);
  EXPECT_NE(DumpParse1, DumpParseDifferent);
}

TEST_F(ClangdVFSTest, CheckVersions) {
  MockFSProvider FS;
  ErrorCheckingDiagConsumer DiagConsumer;
  MockCompilationDatabase CDB;
  // Run ClangdServer synchronously.
  ClangdServer Server(CDB, DiagConsumer, FS,
                      /*AsyncThreadsCount=*/0,
                      /*StorePreamblesInMemory=*/true);

  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  const auto SourceContents = "int a;";
  FS.Files[FooCpp] = SourceContents;
  FS.ExpectedFile = FooCpp;

  // Use default completion options.
  clangd::CodeCompleteOptions CCOpts;

  // No need to sync reparses, because requests are processed on the calling
  // thread.
  FS.Tag = "123";
  Server.addDocument(Context::empty(), FooCpp, SourceContents);
  EXPECT_EQ(
      Server.codeComplete(Context::empty(), FooCpp, Position{0, 0}, CCOpts)
          .get()
          .second.Tag,
      FS.Tag);
  EXPECT_EQ(DiagConsumer.lastVFSTag(), FS.Tag);

  FS.Tag = "321";
  Server.addDocument(Context::empty(), FooCpp, SourceContents);
  EXPECT_EQ(DiagConsumer.lastVFSTag(), FS.Tag);
  EXPECT_EQ(
      Server.codeComplete(Context::empty(), FooCpp, Position{0, 0}, CCOpts)
          .get()
          .second.Tag,
      FS.Tag);
}

// Only enable this test on Unix
#ifdef LLVM_ON_UNIX
TEST_F(ClangdVFSTest, SearchLibDir) {
  // Checks that searches for GCC installation is done through vfs.
  MockFSProvider FS;
  ErrorCheckingDiagConsumer DiagConsumer;
  MockCompilationDatabase CDB;
  CDB.ExtraClangFlags.insert(CDB.ExtraClangFlags.end(),
                             {"-xc++", "-target", "x86_64-linux-unknown",
                              "-m64", "--gcc-toolchain=/randomusr",
                              "-stdlib=libstdc++"});
  // Run ClangdServer synchronously.
  ClangdServer Server(CDB, DiagConsumer, FS,
                      /*AsyncThreadsCount=*/0,
                      /*StorePreamblesInMemory=*/true);

  // Just a random gcc version string
  SmallString<8> Version("4.9.3");

  // A lib dir for gcc installation
  SmallString<64> LibDir("/randomusr/lib/gcc/x86_64-linux-gnu");
  llvm::sys::path::append(LibDir, Version);

  // Put crtbegin.o into LibDir/64 to trick clang into thinking there's a gcc
  // installation there.
  SmallString<64> DummyLibFile;
  llvm::sys::path::append(DummyLibFile, LibDir, "64", "crtbegin.o");
  FS.Files[DummyLibFile] = "";

  SmallString<64> IncludeDir("/randomusr/include/c++");
  llvm::sys::path::append(IncludeDir, Version);

  SmallString<64> StringPath;
  llvm::sys::path::append(StringPath, IncludeDir, "string");
  FS.Files[StringPath] = "class mock_string {};";

  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  const auto SourceContents = R"cpp(
#include <string>
mock_string x;
)cpp";
  FS.Files[FooCpp] = SourceContents;

  // No need to sync reparses, because requests are processed on the calling
  // thread.
  Server.addDocument(Context::empty(), FooCpp, SourceContents);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());

  const auto SourceContentsWithError = R"cpp(
#include <string>
std::string x;
)cpp";
  Server.addDocument(Context::empty(), FooCpp, SourceContentsWithError);
  EXPECT_TRUE(DiagConsumer.hadErrorInLastDiags());
}
#endif // LLVM_ON_UNIX

TEST_F(ClangdVFSTest, ForceReparseCompileCommand) {
  MockFSProvider FS;
  ErrorCheckingDiagConsumer DiagConsumer;
  MockCompilationDatabase CDB;
  ClangdServer Server(CDB, DiagConsumer, FS,
                      /*AsyncThreadsCount=*/0,
                      /*StorePreamblesInMemory=*/true);

  // No need to sync reparses, because reparses are performed on the calling
  // thread.
  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  const auto SourceContents1 = R"cpp(
template <class T>
struct foo { T x; };
)cpp";
  const auto SourceContents2 = R"cpp(
template <class T>
struct bar { T x; };
)cpp";

  FS.Files[FooCpp] = "";
  FS.ExpectedFile = FooCpp;

  // First parse files in C mode and check they produce errors.
  CDB.ExtraClangFlags = {"-xc"};
  Server.addDocument(Context::empty(), FooCpp, SourceContents1);
  EXPECT_TRUE(DiagConsumer.hadErrorInLastDiags());
  Server.addDocument(Context::empty(), FooCpp, SourceContents2);
  EXPECT_TRUE(DiagConsumer.hadErrorInLastDiags());

  // Now switch to C++ mode.
  CDB.ExtraClangFlags = {"-xc++"};
  // Currently, addDocument never checks if CompileCommand has changed, so we
  // expect to see the errors.
  Server.addDocument(Context::empty(), FooCpp, SourceContents1);
  EXPECT_TRUE(DiagConsumer.hadErrorInLastDiags());
  Server.addDocument(Context::empty(), FooCpp, SourceContents2);
  EXPECT_TRUE(DiagConsumer.hadErrorInLastDiags());
  // But forceReparse should reparse the file with proper flags.
  Server.forceReparse(Context::empty(), FooCpp);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());
  // Subsequent addDocument calls should finish without errors too.
  Server.addDocument(Context::empty(), FooCpp, SourceContents1);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());
  Server.addDocument(Context::empty(), FooCpp, SourceContents2);
  EXPECT_FALSE(DiagConsumer.hadErrorInLastDiags());
}

class ClangdThreadingTest : public ClangdVFSTest {};

TEST_F(ClangdThreadingTest, DISABLED_StressTest) {
  // Without 'static' clang gives an error for a usage inside TestDiagConsumer.
  static const unsigned FilesCount = 5;
  const unsigned RequestsCount = 500;
  // Blocking requests wait for the parsing to complete, they slow down the test
  // dramatically, so they are issued rarely. Each
  // BlockingRequestInterval-request will be a blocking one.
  const unsigned BlockingRequestInterval = 40;

  const auto SourceContentsWithoutErrors = R"cpp(
int a;
int b;
int c;
int d;
)cpp";

  const auto SourceContentsWithErrors = R"cpp(
int a = x;
int b;
int c;
int d;
)cpp";

  // Giving invalid line and column number should not crash ClangdServer, but
  // just to make sure we're sometimes hitting the bounds inside the file we
  // limit the intervals of line and column number that are generated.
  unsigned MaxLineForFileRequests = 7;
  unsigned MaxColumnForFileRequests = 10;

  std::vector<SmallString<32>> FilePaths;
  FilePaths.reserve(FilesCount);
  for (unsigned I = 0; I < FilesCount; ++I)
    FilePaths.push_back(getVirtualTestFilePath(std::string("Foo") +
                                               std::to_string(I) + ".cpp"));
  // Mark all of those files as existing.
  llvm::StringMap<std::string> FileContents;
  for (auto &&FilePath : FilePaths)
    FileContents[FilePath] = "";

  ConstantFSProvider FS(buildTestFS(FileContents));

  struct FileStat {
    unsigned HitsWithoutErrors = 0;
    unsigned HitsWithErrors = 0;
    bool HadErrorsInLastDiags = false;
  };

  class TestDiagConsumer : public DiagnosticsConsumer {
  public:
    TestDiagConsumer() : Stats(FilesCount, FileStat()) {}

    void onDiagnosticsReady(
        PathRef File,
        Tagged<std::vector<DiagWithFixIts>> Diagnostics) override {
      StringRef FileIndexStr = llvm::sys::path::stem(File);
      ASSERT_TRUE(FileIndexStr.consume_front("Foo"));

      unsigned long FileIndex = std::stoul(FileIndexStr.str());

      bool HadError = diagsContainErrors(Diagnostics.Value);

      std::lock_guard<std::mutex> Lock(Mutex);
      if (HadError)
        Stats[FileIndex].HitsWithErrors++;
      else
        Stats[FileIndex].HitsWithoutErrors++;
      Stats[FileIndex].HadErrorsInLastDiags = HadError;
    }

    std::vector<FileStat> takeFileStats() {
      std::lock_guard<std::mutex> Lock(Mutex);
      return std::move(Stats);
    }

  private:
    std::mutex Mutex;
    std::vector<FileStat> Stats;
  };

  struct RequestStats {
    unsigned RequestsWithoutErrors = 0;
    unsigned RequestsWithErrors = 0;
    bool LastContentsHadErrors = false;
    bool FileIsRemoved = true;
    std::future<Context> LastRequestFuture;
  };

  std::vector<RequestStats> ReqStats;
  ReqStats.reserve(FilesCount);
  for (unsigned FileIndex = 0; FileIndex < FilesCount; ++FileIndex)
    ReqStats.emplace_back();

  TestDiagConsumer DiagConsumer;
  {
    MockCompilationDatabase CDB;
    ClangdServer Server(CDB, DiagConsumer, FS, getDefaultAsyncThreadsCount(),
                        /*StorePreamblesInMemory=*/true);

    // Prepare some random distributions for the test.
    std::random_device RandGen;

    std::uniform_int_distribution<unsigned> FileIndexDist(0, FilesCount - 1);
    // Pass a text that contains compiler errors to addDocument in about 20% of
    // all requests.
    std::bernoulli_distribution ShouldHaveErrorsDist(0.2);
    // Line and Column numbers for requests that need them.
    std::uniform_int_distribution<int> LineDist(0, MaxLineForFileRequests);
    std::uniform_int_distribution<int> ColumnDist(0, MaxColumnForFileRequests);

    // Some helpers.
    auto UpdateStatsOnAddDocument = [&](unsigned FileIndex, bool HadErrors,
                                        std::future<Context> Future) {
      auto &Stats = ReqStats[FileIndex];

      if (HadErrors)
        ++Stats.RequestsWithErrors;
      else
        ++Stats.RequestsWithoutErrors;
      Stats.LastContentsHadErrors = HadErrors;
      Stats.FileIsRemoved = false;
      Stats.LastRequestFuture = std::move(Future);
    };

    auto UpdateStatsOnRemoveDocument = [&](unsigned FileIndex,
                                           std::future<Context> Future) {
      auto &Stats = ReqStats[FileIndex];

      Stats.FileIsRemoved = true;
      Stats.LastRequestFuture = std::move(Future);
    };

    auto UpdateStatsOnForceReparse = [&](unsigned FileIndex,
                                         std::future<Context> Future) {
      auto &Stats = ReqStats[FileIndex];

      Stats.LastRequestFuture = std::move(Future);
      if (Stats.LastContentsHadErrors)
        ++Stats.RequestsWithErrors;
      else
        ++Stats.RequestsWithoutErrors;
    };

    auto AddDocument = [&](unsigned FileIndex) {
      bool ShouldHaveErrors = ShouldHaveErrorsDist(RandGen);
      auto Future =
          Server.addDocument(Context::empty(), FilePaths[FileIndex],
                             ShouldHaveErrors ? SourceContentsWithErrors
                                              : SourceContentsWithoutErrors);
      UpdateStatsOnAddDocument(FileIndex, ShouldHaveErrors, std::move(Future));
    };

    // Various requests that we would randomly run.
    auto AddDocumentRequest = [&]() {
      unsigned FileIndex = FileIndexDist(RandGen);
      AddDocument(FileIndex);
    };

    auto ForceReparseRequest = [&]() {
      unsigned FileIndex = FileIndexDist(RandGen);
      // Make sure we don't violate the ClangdServer's contract.
      if (ReqStats[FileIndex].FileIsRemoved)
        AddDocument(FileIndex);

      auto Future = Server.forceReparse(Context::empty(), FilePaths[FileIndex]);
      UpdateStatsOnForceReparse(FileIndex, std::move(Future));
    };

    auto RemoveDocumentRequest = [&]() {
      unsigned FileIndex = FileIndexDist(RandGen);
      // Make sure we don't violate the ClangdServer's contract.
      if (ReqStats[FileIndex].FileIsRemoved)
        AddDocument(FileIndex);

      auto Future =
          Server.removeDocument(Context::empty(), FilePaths[FileIndex]);
      UpdateStatsOnRemoveDocument(FileIndex, std::move(Future));
    };

    auto CodeCompletionRequest = [&]() {
      unsigned FileIndex = FileIndexDist(RandGen);
      // Make sure we don't violate the ClangdServer's contract.
      if (ReqStats[FileIndex].FileIsRemoved)
        AddDocument(FileIndex);

      Position Pos{LineDist(RandGen), ColumnDist(RandGen)};
      // FIXME(ibiryukov): Also test async completion requests.
      // Simply putting CodeCompletion into async requests now would make
      // tests slow, since there's no way to cancel previous completion
      // requests as opposed to AddDocument/RemoveDocument, which are implicitly
      // cancelled by any subsequent AddDocument/RemoveDocument request to the
      // same file.
      Server
          .codeComplete(Context::empty(), FilePaths[FileIndex], Pos,
                        clangd::CodeCompleteOptions())
          .wait();
    };

    auto FindDefinitionsRequest = [&]() {
      unsigned FileIndex = FileIndexDist(RandGen);
      // Make sure we don't violate the ClangdServer's contract.
      if (ReqStats[FileIndex].FileIsRemoved)
        AddDocument(FileIndex);

      Position Pos{LineDist(RandGen), ColumnDist(RandGen)};
      ASSERT_TRUE(!!Server.findDefinitions(Context::empty(),
                                           FilePaths[FileIndex], Pos));
    };

    std::vector<std::function<void()>> AsyncRequests = {
        AddDocumentRequest, ForceReparseRequest, RemoveDocumentRequest};
    std::vector<std::function<void()>> BlockingRequests = {
        CodeCompletionRequest, FindDefinitionsRequest};

    // Bash requests to ClangdServer in a loop.
    std::uniform_int_distribution<int> AsyncRequestIndexDist(
        0, AsyncRequests.size() - 1);
    std::uniform_int_distribution<int> BlockingRequestIndexDist(
        0, BlockingRequests.size() - 1);
    for (unsigned I = 1; I <= RequestsCount; ++I) {
      if (I % BlockingRequestInterval != 0) {
        // Issue an async request most of the time. It should be fast.
        unsigned RequestIndex = AsyncRequestIndexDist(RandGen);
        AsyncRequests[RequestIndex]();
      } else {
        // Issue a blocking request once in a while.
        auto RequestIndex = BlockingRequestIndexDist(RandGen);
        BlockingRequests[RequestIndex]();
      }
    }

    // Wait for last requests to finish.
    for (auto &ReqStat : ReqStats) {
      if (!ReqStat.LastRequestFuture.valid())
        continue; // We never ran any requests for this file.

      // Future should be ready much earlier than in 5 seconds, the timeout is
      // there to check we won't wait indefinitely.
      ASSERT_EQ(ReqStat.LastRequestFuture.wait_for(std::chrono::seconds(5)),
                std::future_status::ready);
    }
  } // Wait for ClangdServer to shutdown before proceeding.

  // Check some invariants about the state of the program.
  std::vector<FileStat> Stats = DiagConsumer.takeFileStats();
  for (unsigned I = 0; I < FilesCount; ++I) {
    if (!ReqStats[I].FileIsRemoved) {
      ASSERT_EQ(Stats[I].HadErrorsInLastDiags,
                ReqStats[I].LastContentsHadErrors);
    }

    ASSERT_LE(Stats[I].HitsWithErrors, ReqStats[I].RequestsWithErrors);
    ASSERT_LE(Stats[I].HitsWithoutErrors, ReqStats[I].RequestsWithoutErrors);
  }
}

TEST_F(ClangdVFSTest, CheckSourceHeaderSwitch) {
  MockFSProvider FS;
  ErrorCheckingDiagConsumer DiagConsumer;
  MockCompilationDatabase CDB;

  ClangdServer Server(CDB, DiagConsumer, FS, getDefaultAsyncThreadsCount(),
                      /*StorePreamblesInMemory=*/true);

  auto SourceContents = R"cpp(
  #include "foo.h"
  int b = a;
  )cpp";

  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  auto FooH = getVirtualTestFilePath("foo.h");
  auto Invalid = getVirtualTestFilePath("main.cpp");

  FS.Files[FooCpp] = SourceContents;
  FS.Files[FooH] = "int a;";
  FS.Files[Invalid] = "int main() { \n return 0; \n }";

  llvm::Optional<Path> PathResult = Server.switchSourceHeader(FooCpp);
  EXPECT_TRUE(PathResult.hasValue());
  ASSERT_EQ(PathResult.getValue(), FooH);

  PathResult = Server.switchSourceHeader(FooH);
  EXPECT_TRUE(PathResult.hasValue());
  ASSERT_EQ(PathResult.getValue(), FooCpp);

  SourceContents = R"c(
  #include "foo.HH"
  int b = a;
  )c";

  // Test with header file in capital letters and different extension, source
  // file with different extension
  auto FooC = getVirtualTestFilePath("bar.c");
  auto FooHH = getVirtualTestFilePath("bar.HH");

  FS.Files[FooC] = SourceContents;
  FS.Files[FooHH] = "int a;";

  PathResult = Server.switchSourceHeader(FooC);
  EXPECT_TRUE(PathResult.hasValue());
  ASSERT_EQ(PathResult.getValue(), FooHH);

  // Test with both capital letters
  auto Foo2C = getVirtualTestFilePath("foo2.C");
  auto Foo2HH = getVirtualTestFilePath("foo2.HH");
  FS.Files[Foo2C] = SourceContents;
  FS.Files[Foo2HH] = "int a;";

  PathResult = Server.switchSourceHeader(Foo2C);
  EXPECT_TRUE(PathResult.hasValue());
  ASSERT_EQ(PathResult.getValue(), Foo2HH);

  // Test with source file as capital letter and .hxx header file
  auto Foo3C = getVirtualTestFilePath("foo3.C");
  auto Foo3HXX = getVirtualTestFilePath("foo3.hxx");

  SourceContents = R"c(
  #include "foo3.hxx"
  int b = a;
  )c";

  FS.Files[Foo3C] = SourceContents;
  FS.Files[Foo3HXX] = "int a;";

  PathResult = Server.switchSourceHeader(Foo3C);
  EXPECT_TRUE(PathResult.hasValue());
  ASSERT_EQ(PathResult.getValue(), Foo3HXX);

  // Test if asking for a corresponding file that doesn't exist returns an empty
  // string.
  PathResult = Server.switchSourceHeader(Invalid);
  EXPECT_FALSE(PathResult.hasValue());
}

TEST_F(ClangdThreadingTest, NoConcurrentDiagnostics) {
  class NoConcurrentAccessDiagConsumer : public DiagnosticsConsumer {
  public:
    NoConcurrentAccessDiagConsumer(std::promise<void> StartSecondReparse)
        : StartSecondReparse(std::move(StartSecondReparse)) {}

    void onDiagnosticsReady(
        PathRef File,
        Tagged<std::vector<DiagWithFixIts>> Diagnostics) override {

      std::unique_lock<std::mutex> Lock(Mutex, std::try_to_lock_t());
      ASSERT_TRUE(Lock.owns_lock())
          << "Detected concurrent onDiagnosticsReady calls for the same file.";
      if (FirstRequest) {
        FirstRequest = false;
        StartSecondReparse.set_value();
        // Sleep long enough for the second request to be processed.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
    }

  private:
    std::mutex Mutex;
    bool FirstRequest = true;
    std::promise<void> StartSecondReparse;
  };

  const auto SourceContentsWithoutErrors = R"cpp(
int a;
int b;
int c;
int d;
)cpp";

  const auto SourceContentsWithErrors = R"cpp(
int a = x;
int b;
int c;
int d;
)cpp";

  auto FooCpp = getVirtualTestFilePath("foo.cpp");
  llvm::StringMap<std::string> FileContents;
  FileContents[FooCpp] = "";
  ConstantFSProvider FS(buildTestFS(FileContents));

  std::promise<void> StartSecondReparsePromise;
  std::future<void> StartSecondReparse = StartSecondReparsePromise.get_future();

  NoConcurrentAccessDiagConsumer DiagConsumer(
      std::move(StartSecondReparsePromise));

  MockCompilationDatabase CDB;
  ClangdServer Server(CDB, DiagConsumer, FS, 4,
                      /*StorePreamblesInMemory=*/true);
  Server.addDocument(Context::empty(), FooCpp, SourceContentsWithErrors);
  StartSecondReparse.wait();

  auto Future =
      Server.addDocument(Context::empty(), FooCpp, SourceContentsWithoutErrors);
  Future.wait();
}
#endif

namespace {
const char *STORAGE_FILE_NAME = "test.index";
const unsigned VERSION_NUM = 1;

void deleteStorageFileIfExists() {
  if (llvm::sys::fs::exists(STORAGE_FILE_NAME)) {
    llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);
  }
}
}

class ClangdIndexDataStorageTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

TEST_F(ClangdIndexDataStorageTest, TestCreate) {
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    ASSERT_TRUE (llvm::sys::fs::exists(STORAGE_FILE_NAME));
    ASSERT_EQ(Storage.getVersion(), VERSION_NUM);
  }

  uint64_t FileSizeResult;
  ASSERT_EQ(llvm::sys::fs::file_size(STORAGE_FILE_NAME, FileSizeResult),
      std::error_code());
  ASSERT_EQ(FileSizeResult, ClangdIndexDataPiece::PIECE_SIZE);
}

TEST_F(ClangdIndexDataStorageTest, TestCreateReopenEmpty) {
  const unsigned EXPECTED_VERSION_NUM = 1234;
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, EXPECTED_VERSION_NUM);
    ASSERT_TRUE (llvm::sys::fs::exists(STORAGE_FILE_NAME));
    ASSERT_EQ(Storage.getVersion(), EXPECTED_VERSION_NUM);
    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, EXPECTED_VERSION_NUM);
    ASSERT_EQ(Storage.getVersion(), EXPECTED_VERSION_NUM);
  }
}

TEST_F(ClangdIndexDataStorageTest, TestReadWritePiece) {
  ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
  char BuffWrite[ClangdIndexDataPiece::PIECE_SIZE] = { '1', '2', '3' };
  BuffWrite [ClangdIndexDataPiece::PIECE_SIZE - 1] = '\0';
  Storage.writePiece(BuffWrite, 0);
  char BuffRead[ClangdIndexDataPiece::PIECE_SIZE];
  Storage.readPiece(BuffRead, 0);
  ASSERT_EQ(strcmp(BuffWrite, BuffRead), 0);
}

TEST_F(ClangdIndexDataStorageTest, TestMalloc) {
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    // Try to malloc all the valid sizes
    for (unsigned CurDataSize = 0;
        CurDataSize <= ClangdIndexDataStorage::MAX_MALLOC_SIZE; ++CurDataSize) {
      RecordPointer Rec = Storage.mallocRecord(CurDataSize);
      ASSERT_GE(Rec, ClangdIndexDataStorage::MALLOC_AREA_START);
    }
    Storage.endWrite();
    llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);
  }

  // Test reusing a free block that was left-over from previous malloc
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    // Choose a malloc size (and its header) that will fit nicely in a block
    // size. So we don't have to worry about rounding up to the next valid
    // block size
    const static unsigned int SMALL_MALLOC_SIZE = 10
        * ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT
        - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    const static unsigned int LEFT_OVER_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    // Make sure some assumptions about the constants are true
    ASSERT_TRUE(ClangdIndexDataStorage::MAX_MALLOC_SIZE > SMALL_MALLOC_SIZE
            && ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
                > ClangdIndexDataStorage::MIN_BLOCK_SIZE);
    RecordPointer Rec = Storage.mallocRecord(SMALL_MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    RecordPointer LeftOverMallocRec = Storage.mallocRecord(
        LEFT_OVER_MALLOC_SIZE);
    // If this malloc is right after the first one, we have successfully reused
    // a free block
    ASSERT_EQ(LeftOverMallocRec,
        Rec + ClangdIndexDataStorage::BLOCK_HEADER_SIZE + SMALL_MALLOC_SIZE);

    Storage.endWrite();
    llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);
  }

  // Test not reusing left-over from previous malloc because second malloc is
  // just too big
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    // Choose a malloc size (and its header) that will fit nicely in a block
    // size. So we don't have to worry about rounding up to the next valid
    // block size
    const static unsigned int SMALL_MALLOC_SIZE = 10
        * ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT
        - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    // Go a bit over the size that would fit in the free block
    const static unsigned int SECOND_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            + ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT;
    // Make sure some assumptions about the constants are true
    ASSERT_TRUE(ClangdIndexDataStorage::MAX_MALLOC_SIZE > SMALL_MALLOC_SIZE
            && ClangdIndexDataStorage::MAX_MALLOC_SIZE - SMALL_MALLOC_SIZE
                > ClangdIndexDataStorage::MIN_BLOCK_SIZE);
    RecordPointer Rec = Storage.mallocRecord(SMALL_MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    RecordPointer SecondMallocRec = Storage.mallocRecord(SECOND_MALLOC_SIZE);
    ASSERT_EQ(SecondMallocRec, Rec + ClangdIndexDataStorage::MAX_BLOCK_SIZE);

    Storage.endWrite();
    llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);
  }

  // Test linked list of free blocks. Do mallocs so that two free blocks of the
  // same size are created than malloc so they are used in order.
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    // Choose a malloc size (and its header) that will fit nicely in a block
    // size. So we don't have to worry about rounding up to the next valid
    // block size
    const static unsigned int BIG_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_BLOCK_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            - 10 * ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT;
    // Size that would have fit without considering the min block size
    // necessary for the left over free block
    const static unsigned int LEFT_OVER_MALLOC_SIZE =
        ClangdIndexDataStorage::MAX_MALLOC_SIZE - BIG_MALLOC_SIZE
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    // Make sure some assumptions about the constants are true
    ASSERT_TRUE(ClangdIndexDataStorage::MAX_MALLOC_SIZE > BIG_MALLOC_SIZE
            && ClangdIndexDataStorage::MAX_MALLOC_SIZE - BIG_MALLOC_SIZE
                >= ClangdIndexDataStorage::MIN_BLOCK_SIZE);
    RecordPointer RecMalloc1 = Storage.mallocRecord(BIG_MALLOC_SIZE);
    ASSERT_EQ(RecMalloc1, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    RecordPointer RecMalloc2 = Storage.mallocRecord(BIG_MALLOC_SIZE);
    ASSERT_EQ(RecMalloc2, RecMalloc1 + ClangdIndexDataStorage::MAX_BLOCK_SIZE);
    RecordPointer LeftOver1Rec = Storage.mallocRecord(LEFT_OVER_MALLOC_SIZE);
    // The last free block is the first in the linked list of free blocks of
    // that size
    ASSERT_EQ(LeftOver1Rec,
        RecMalloc2 + ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            + BIG_MALLOC_SIZE);
    RecordPointer LeftOver2Rec = Storage.mallocRecord(LEFT_OVER_MALLOC_SIZE);
    ASSERT_EQ(LeftOver2Rec,
        RecMalloc1 + ClangdIndexDataStorage::BLOCK_HEADER_SIZE
            + BIG_MALLOC_SIZE);
    // No free block left
    RecordPointer LeftOver3Rec = Storage.mallocRecord(LEFT_OVER_MALLOC_SIZE);
    ASSERT_EQ(LeftOver3Rec,
        RecMalloc2 + ClangdIndexDataStorage::MAX_BLOCK_SIZE);

    Storage.endWrite();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetInt8) {
  RecordPointer Rec;
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    Rec = Storage.mallocRecord(sizeof(int8_t) * 3);
    Storage.putInt8(Rec, INT8_MIN);
    Storage.putInt8(Rec + sizeof(int8_t), INT8_MAX);
    Storage.putInt8(Rec + sizeof(int8_t) * 2, 0);

    ASSERT_EQ(Storage.getInt8(Rec), INT8_MIN);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t)),
        INT8_MAX);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t) * 2),
        0);
    Storage.endWrite();

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);

    ASSERT_EQ(Storage.getInt8(Rec), INT8_MIN);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t)), INT8_MAX);
    ASSERT_EQ(Storage.getInt8(Rec + sizeof(int8_t) * 2), 0);
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetInt32) {
  RecordPointer Rec;
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    Rec = Storage.mallocRecord(ClangdIndexDataStorage::INT32_SIZE * 3);
    Storage.putInt32(Rec, INT32_MIN);
    Storage.putInt32(Rec + ClangdIndexDataStorage::INT32_SIZE, INT32_MAX);
    Storage.putInt32(Rec + ClangdIndexDataStorage::INT32_SIZE * 2, 0);

    ASSERT_EQ(Storage.getInt32(Rec), INT32_MIN);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE),
        INT32_MAX);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE * 2),
        0);
    Storage.endWrite();

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);

    ASSERT_EQ(Storage.getInt32(Rec), INT32_MIN);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE),
        INT32_MAX);
    ASSERT_EQ(Storage.getInt32(Rec + ClangdIndexDataStorage::INT32_SIZE * 2),
        0);
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetData) {
  struct MyDataStruct {
    int Foo;
    int Bar;
  };
  MyDataStruct ObjPut;
  ObjPut.Foo = 0xABCD;
  ObjPut.Bar = 0xEF01;

  RecordPointer Rec;
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    Rec = Storage.mallocRecord(sizeof(MyDataStruct));
    Storage.putData(Rec, &ObjPut, sizeof(MyDataStruct));

    MyDataStruct ObjGet;
    Storage.getData(Rec, &ObjGet, sizeof(MyDataStruct));
    ASSERT_EQ(ObjGet.Foo, ObjPut.Foo);
    ASSERT_EQ(ObjGet.Bar, ObjPut.Bar);
    Storage.endWrite();

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);

    MyDataStruct ObjGet;
    Storage.getData(Rec, &ObjGet, sizeof(MyDataStruct));
    ASSERT_EQ(ObjGet.Foo, ObjPut.Foo);
    ASSERT_EQ(ObjGet.Bar, ObjPut.Bar);
    Storage.endWrite();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestStartEndWrite) {
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    //Commented this out because it caused crash reporters to show every time
    //the test was executed. Not sure what the best practice for this is.
    //ASSERT_DEATH_IF_SUPPORTED(Storage.mallocRecord(1), ".*write mode*.");

    // Shouldn't do anything, write not started
    Storage.endWrite();

    Storage.startWrite();
    RecordPointer Rec1 = Storage.mallocRecord(
        ClangdIndexDataStorage::MAX_MALLOC_SIZE);
    Storage.putInt32(Rec1, 123);
    Storage.endWrite();
    ASSERT_EQ(Storage.getInt32(Rec1), 123);

    // Flush can be called before end of write, the index will still be in
    // write mode
    Storage.startWrite();
    RecordPointer Rec2 = Storage.mallocRecord(
        ClangdIndexDataStorage::MAX_MALLOC_SIZE);
    Storage.putInt32(Rec2, 456);
    Storage.flush();
    RecordPointer Rec3 = Storage.mallocRecord(
        ClangdIndexDataStorage::MAX_MALLOC_SIZE);
    Storage.putInt32(Rec3, 789);
    Storage.endWrite();
    ASSERT_EQ(Storage.getInt32(Rec2), 456);
    ASSERT_EQ(Storage.getInt32(Rec3), 789);

    Storage.flush();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestFree) {
  // A simple malloc, delete, then malloc should end up at the same spot
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    const static unsigned MALLOC_SIZE =
        ClangdIndexDataStorage::BLOCK_SIZE_INCREMENT * 10
            - ClangdIndexDataStorage::BLOCK_HEADER_SIZE;
    RecordPointer Rec = Storage.mallocRecord(MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    Storage.freeRecord(Rec);
    Rec = Storage.mallocRecord(MALLOC_SIZE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);

    Storage.endWrite();
    llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);
  }

  // Malloc all possible sizes, delete all, then mallocs should end up reusing
  // all free blocks
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    // Try to malloc all the valid sizes
    std::vector<RecordPointer> Records;
    RecordPointer MaxRecord;
    for (unsigned CurDataSize = 0;
        CurDataSize <= ClangdIndexDataStorage::MAX_MALLOC_SIZE; ++CurDataSize) {
      RecordPointer Rec = Storage.mallocRecord(CurDataSize);
      ASSERT_GE(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
              + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
      Records.push_back(Rec);
      MaxRecord = std::max(Rec, MaxRecord);
    }

    // Delete everything
    for (auto Rec : Records) {
      Storage.freeRecord(Rec);
    }

    // Realloc everything, they should all fit in previously freed blocks
    // (<= MaxRecord from previous).
    for (unsigned CurDataSize = 0;
        CurDataSize <= ClangdIndexDataStorage::MAX_MALLOC_SIZE; ++CurDataSize) {
      RecordPointer Rec = Storage.mallocRecord(CurDataSize);
      ASSERT_GE(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
              + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
      ASSERT_LE(Rec, MaxRecord);
      if (CurDataSize == 0) {
        break;
      }
    }

    Storage.endWrite();
  }
}

TEST_F(ClangdIndexDataStorageTest, TestPutGetRec) {
  const int32_t SOME_INT_VALUE = 1245678;

  // Malloc an integer, make a pointer to it
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    RecordPointer Rec = Storage.mallocRecord(
        ClangdIndexDataStorage::INT32_SIZE);
    Storage.putInt32(Rec, SOME_INT_VALUE);
    ASSERT_EQ(Rec, ClangdIndexDataStorage::MALLOC_AREA_START
            + ClangdIndexDataStorage::BLOCK_HEADER_SIZE);
    Storage.putRecPtr(ClangdIndexDataStorage::DATA_AREA, Rec);
    Storage.endWrite();
    Storage.flush();
  }

  // Read back the int using the pointer
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    RecordPointer RecPtr = Storage.getRecPtr(ClangdIndexDataStorage::DATA_AREA);
    ASSERT_EQ(Storage.getInt32(RecPtr), SOME_INT_VALUE);
  }
}

class ClangdIndexStringTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

TEST_F(ClangdIndexStringTest, TestPutGetString) {
  std::vector<RecordPointer> Records;
  std::vector<std::string> WrittenStrings;
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();

    // Try to write strings of all the valid sizes
    for (unsigned CurStringSize = 0;
        CurStringSize <= ClangdIndexString::MAX_STRING_SIZE; ++CurStringSize) {
      std::vector<char> Str(CurStringSize + 1);
      Str[CurStringSize] = '\0';
      // Write some characters
      for (unsigned I = 0; I < CurStringSize; ++I) {
        Str[I] = 'A';
      }

      std::string CurString(Str.data());
      RecordPointer Rec = ClangdIndexString(Storage, CurString).getRecord();
      // Make sure we can read back the string we just created
      ASSERT_EQ(ClangdIndexString(Storage, Rec).getString().compare(CurString),
          0);

      // Save those for later when we reopen the file
      Records.push_back(Rec);
      WrittenStrings.push_back(CurString);
    }

    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);

    // Make sure all the strings are there after reopening the file
    for (size_t I = 0; I < Records.size(); ++I) {
      // Make sure we can read back the string we just created
      ASSERT_EQ(ClangdIndexString(Storage, Records[I]).getString().compare(
              WrittenStrings[I]), 0);
    }

    Storage.flush();
  }
}
TEST_F(ClangdIndexStringTest, TestLargeString) {
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    unsigned Length = ClangdIndexString::MAX_STRING_SIZE + 2;
    std::vector<char> Str(Length);
    for (unsigned I = 0; I < Length; ++I) {
      Str[I] = 'A';
    }
    Str[Length] = '\0';
    //Commented this out because it caused crash reporters to show every time
    //the test was executed. Not sure what the best practice for this is.
    //ASSERT_DEATH_IF_SUPPORTED(ClangdIndexString(Storage, Str.data()),
    //    ".*not supported.*");

    Storage.flush();
  }
}

class ClangdBTreeTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

class StringComparator : public BTreeComparator {
  ClangdIndexDataStorage &Storage;

public:
  StringComparator(ClangdIndexDataStorage &Storage) : Storage(Storage) {
  }

  int compare(RecordPointer Record1, RecordPointer Record2) override {
    std::string Str1 = ClangdIndexString(Storage, Record1).getString();
    std::string Str2 = ClangdIndexString(Storage, Record2).getString();
    return Str1.compare(Str2);
  }
};

class StringVisitor: public BTreeVisitor {

  std::string SearchedString;
  ClangdIndexDataStorage &Storage;
  bool IsFound;
  RecordPointer Result;

public:
  StringVisitor(std::string SearchedString, ClangdIndexDataStorage &Storage) :
      SearchedString(SearchedString), Storage(Storage), IsFound(false), Result(
          0) {
  }

  int compare(RecordPointer Record) override {
    std::string Current = ClangdIndexString(Storage, Record).getString();
    return Current.compare(SearchedString);
  }

  void visit(RecordPointer Record) override {
    IsFound = true;
    Result = Record;
  }

  bool isFound() {
    return IsFound;
  }

  RecordPointer getResult() {
    return Result;
  }
};

TEST_F(ClangdBTreeTest, TestInsert) {
  // Insert a number of strings and check if there are present after
  const int NUM_CHECKED = 1000;
  std::string TEST_STRING_PREFIX = "string";
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      ClangdIndexString Str(Storage, SS.str());
      Tree.insert(Str.getRecord());
    }
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      StringVisitor Visitor(SS.str(), Storage);
      Tree.accept(Visitor);
      ASSERT_TRUE(Visitor.isFound());
    }
  }
}

TEST_F(ClangdBTreeTest, TestInsertSimple) {
  // Insert a number of strings and check if there are present after
  std::string TEST_STRING_PREFIX = "string";
  ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
  Storage.startWrite();
  StringComparator Comp(Storage);
  BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 2);
  std::vector<std::string> Letters =
      { "A", "B", "C", "D", "E", "F" };
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
}

TEST_F(ClangdBTreeTest, TestInsertMuchMore) {
  // Insert a number of strings and check if there are present after
  const int NUM_CHECKED = 50000;
  std::string TEST_STRING_PREFIX = "string";
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      ClangdIndexString Str(Storage, SS.str());
      Tree.insert(Str.getRecord());

      for (int J = 0; J <= 0; ++J) {
        std::stringstream SS2;
        SS2 << TEST_STRING_PREFIX << J;
        StringVisitor Visitor(SS2.str(), Storage);
        Tree.accept(Visitor);
        bool found = Visitor.isFound();
        if (!found) {
          std::cerr << SS2.str() << std::endl;
        }
        ASSERT_TRUE(found);
      }
    }
    Storage.flush();
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 1; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      StringVisitor Visitor(SS.str(), Storage);
      Tree.accept(Visitor);
      bool found = Visitor.isFound();
      if (!found) {
        std::cerr << SS.str() << std::endl;
      }
      ASSERT_TRUE(found);
    }

    // Also test that we can match all of them with a "multi match" visitor.

    class AllMatch : public BTreeVisitor {
      int Total = 0;
    public:
      int compare(RecordPointer Record) override {
        return 0;
      }
      void visit(RecordPointer Record) override {
        Total++;
      }
      int getTotal() {
        return Total;
      }
    };
    AllMatch V;
    Tree.accept(V);
    ASSERT_EQ(V.getTotal(), NUM_CHECKED);
  }
}

TEST_F(ClangdBTreeTest, TestInsertBackwards) {
  // Insert a number of strings and check if there are present after.
  // This inserts them backwards as this will it hit different code paths.
  const int NUM_CHECKED = 1000;
  std::string TEST_STRING_PREFIX = "string";
  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = NUM_CHECKED - 1; I >= 0; --I) {
      std::stringstream ss;
      ss << TEST_STRING_PREFIX << I;
      ClangdIndexString Str = ClangdIndexString(Storage, ss.str());
      Tree.insert(Str.getRecord());
    }
  }

  {
    ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
    Storage.startWrite();
    StringComparator Comp(Storage);
    BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 4);
    for (int I = 0; I < NUM_CHECKED; ++I) {
      std::stringstream SS;
      SS << TEST_STRING_PREFIX << I;
      StringVisitor Visitor(SS.str(), Storage);
      Tree.accept(Visitor);
      ASSERT_TRUE(Visitor.isFound());
    }
  }
}

void testStringDeletion(std::string StringToDelete,
    std::vector<std::string> &CurrentStrings, BTree &Tree,
    ClangdIndexDataStorage &Storage) {
  StringVisitor SV(StringToDelete, Storage);
  Tree.accept(SV);
  std::string FoundString =
      ClangdIndexString(Storage, SV.getResult()).getString();
  if (!SV.isFound()) {
    std::cerr << " string not found in tree: " << StringToDelete << "\n";
  }
  ASSERT_TRUE(SV.isFound());
  ASSERT_EQ(StringToDelete, FoundString);
  ASSERT_TRUE(Tree.remove(SV.getResult()));

  StringVisitor SVDeleted(StringToDelete, Storage);
  Tree.accept(SVDeleted);
  ASSERT_FALSE(SVDeleted.isFound());
  CurrentStrings.erase(std::remove(CurrentStrings.begin(), CurrentStrings.end(),
          StringToDelete));

  // Make sure all the other letters are still there
  for (auto Letter : CurrentStrings) {
    StringVisitor SV(Letter, Storage);
    Tree.accept(SV);
    std::string FoundString =
        ClangdIndexString(Storage, SV.getResult()).getString();
    ASSERT_TRUE(SV.isFound());
    ASSERT_EQ(Letter, FoundString);
  }
}

TEST_F(ClangdBTreeTest, TestRemove) {
  ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
  Storage.startWrite();

  StringComparator Comp(Storage);
  BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 3);

  // Remove on empty tree. Nothing should happen.
  ASSERT_FALSE(Tree.remove(0));

  std::vector<std::string> Letters =
      { "D", "E", "G", "J", "K", "M", "N", "O", "P", "R", "S", "X", "Y", "Z",
          "V", "A", "C", "T", "U", "B", "Q", "L", "F" };
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }

  // Delete F, case 1: Simple deletion from a leaf
  testStringDeletion("F", Letters, Tree, Storage);

  // Delete M, case 2a: key found in currently visited internal node. Find a
  // key in *previous* node to replace it.
  testStringDeletion("M", Letters, Tree, Storage);

  // Delete G, case 2c: key found in currently visited internal node,
  // previous and next child nodes don't have enough keys to give one away.
  // Merge key and next child node into previous child node then delete key.
  testStringDeletion("G", Letters, Tree, Storage);

  // Delete D, case 3b: key not found in currently visited internal node.
  // The next node to be visited doesn't contain enough keys.
  // Both sibling nodes (only one in case of left-most or right-most) don't have
  // enough keys to give one away.
  // Merge key and sibling with next node then recurse into it.
  testStringDeletion("D", Letters, Tree, Storage);

  // Delete B, case 3a: key not found in currently visited internal node.
  // The next node to be visited doesn't contain enough keys. One of the sibling
  // nodes has enough keys to give one away.
  // Push up the given away key to current node and push down a key do next node
  // then recurse into it. This case is the *next* sibling has extra keys to
  // give away.
  testStringDeletion("B", Letters, Tree, Storage);

  // Delete U, case 3a, symmetrical case: *previous* sibling has extra keys to
  // give away.
  testStringDeletion("U", Letters, Tree, Storage);

  // Delete Z, case 3b, key in right-most child node
  testStringDeletion("Z", Letters, Tree, Storage);

  // Delete V, case 1
  testStringDeletion("V", Letters, Tree, Storage);

  // Delete S, case 2b: key found in currently visited internal node. Find a
  // key in *next* node to replace it.
  testStringDeletion("S", Letters, Tree, Storage);

  // Delete X, case 3b
  testStringDeletion("X", Letters, Tree, Storage);

  // Delete more things to get to next case (2c with new root)
  testStringDeletion("A", Letters, Tree, Storage);
  testStringDeletion("C", Letters, Tree, Storage);
  testStringDeletion("E", Letters, Tree, Storage);
  testStringDeletion("J", Letters, Tree, Storage);
  testStringDeletion("K", Letters, Tree, Storage);
  testStringDeletion("L", Letters, Tree, Storage);
  testStringDeletion("N", Letters, Tree, Storage);
  testStringDeletion("O", Letters, Tree, Storage);
  // The tree should now be like this:
  //
  //      |
  //    Y
  //      |
  //    T
  //      |
  //R
  //      |
  //    Q
  //      |
  //    P
  //      |
  // Case 2c with new root
  testStringDeletion("R", Letters, Tree, Storage);

  std::vector<std::string> Copy = Letters;
  // Delete everything remaining
  for (auto Letter : Copy) {
    testStringDeletion(Letter, Letters, Tree, Storage);
  }

  // Test delete non-existent
  ClangdIndexString Str(Storage, "A");
  ASSERT_FALSE(Tree.remove(Str.getRecord()));


  // Make a new set of letters for more tests
  Letters =
      { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
          "O", "P", "Q", "R", "S", "T", "U"};
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
  // 2b but in this case, finding the lowest key has to go through multiple
  // internal nodes. So this tests the algorithm for proper recursion.
  testStringDeletion("I", Letters, Tree, Storage);
  std::vector<std::string> MoreLetter = {"H1", "H2", "H3", "H4"};
  Letters.insert(Letters.end(), MoreLetter.begin(), MoreLetter.end());
  for (auto Letter : MoreLetter) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
  // 2a but in this case, finding the highest key has to go through multiple
  // internal nodes. So this tests the algorithm for proper recursion.
  testStringDeletion("J", Letters, Tree, Storage);

  Storage.endWrite();
}

TEST_F(ClangdBTreeTest, TestDump) {
  ClangdIndexDataStorage Storage(STORAGE_FILE_NAME, VERSION_NUM);
  Storage.startWrite();

  StringComparator Comp(Storage);
  BTree Tree(Storage, ClangdIndexDataStorage::DATA_AREA, Comp, 3);

  //Dump initially empty tree. Should result in empty string stream.
  std::string StreamBuffer;
  llvm::raw_string_ostream Stream(StreamBuffer);
  Tree.dump([](RecordPointer Rec, llvm::raw_ostream &OS) {OS << "A";}, Stream);
  ASSERT_TRUE(Stream.str().empty());

  std::vector<std::string> Letters =
      { "D", "E", "G", "J", "K", "M", "N", "O", "P", "R", "S", "X", "Y", "Z",
          "V", "A", "C", "T", "U", "B", "Q", "L" };
  for (auto Letter : Letters) {
    Tree.insert(ClangdIndexString(Storage, Letter).getRecord());
  }
  Tree.dump([&Storage](RecordPointer Rec, llvm::raw_ostream &OS) {
    OS << ClangdIndexString(Storage, Rec).getString();
  }, Stream);
  ASSERT_TRUE(!Stream.str().empty());

  // Test empty but initialized (non-null root node)
  for (auto Letter : Letters) {
    StringVisitor SV(Letter, Storage);
    Tree.accept(SV);
    RecordPointer Result = SV.getResult();
    ASSERT_NE(Result, 0);
    ASSERT_TRUE(Tree.remove(SV.getResult()));
  }

  std::string StreamBuffer2;
  llvm::raw_string_ostream Stream2(StreamBuffer2);
  Tree.dump([&Storage](RecordPointer Rec, llvm::raw_ostream &OS) {
    OS << ClangdIndexString(Storage, Rec).getString();
  }, Stream2);
  ASSERT_TRUE(!Stream2.str().empty());

  Storage.endWrite();
}

class ClangdIndexSymbolTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

TEST_F(ClangdIndexSymbolTest, TestCreateAndGetters) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");

  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Symbol = std::move(Symbols[0]);
    ASSERT_TRUE(Symbol);
    ASSERT_EQ(Symbol->getUsr(), TEST_USR);
    ASSERT_FALSE(Symbol->getFirstOccurrence());
    ASSERT_NE(Symbol->getRecord(), 0);
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Symbol = std::move(Symbols[0]);
    ASSERT_TRUE(Symbol);
    ASSERT_EQ(Symbol->getUsr(), TEST_USR);
    ASSERT_FALSE(Symbol->getFirstOccurrence());
    ASSERT_NE(Symbol->getRecord(), 0);
  }
}


class ClangdIndexOccurrenceTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

TEST_F(ClangdIndexOccurrenceTest, TestCreateAndGetters) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");
  const IndexSourceLocation LOC_START = 12;
  const IndexSourceLocation LOC_END = 23;

  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));


    IndexFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Occurrence = Symbols[0]->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_NE(Occurrence->getRecord(), 0);
    ASSERT_EQ(Occurrence->getPath(), TEST_FILE_PATH);
    ASSERT_EQ(Occurrence->getLocStart(), LOC_START);
    ASSERT_EQ(Occurrence->getLocEnd(), LOC_END);
    ASSERT_FALSE(Occurrence->getNextInFile());
    ASSERT_FALSE(Occurrence->getNextOccurrence());
    ASSERT_EQ(Occurrence->getRoles(), static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Occurrence = Symbols[0]->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_NE(Occurrence->getRecord(), 0);
    ASSERT_EQ(Occurrence->getPath(), TEST_FILE_PATH);
    ASSERT_EQ(Occurrence->getLocStart(), LOC_START);
    ASSERT_EQ(Occurrence->getLocEnd(), LOC_END);
    ASSERT_FALSE(Occurrence->getNextInFile());
    ASSERT_FALSE(Occurrence->getNextOccurrence());
    ASSERT_EQ(Occurrence->getRoles(), static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
  }
}


class ClangdIndexFileTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

TEST_F(ClangdIndexFileTest, TestCreateAndGetters) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    ASSERT_EQ(FileGet->getPath(), TEST_FILE_PATH);
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    ASSERT_EQ(File->getPath(), TEST_FILE_PATH);
  }
}

TEST_F(ClangdIndexFileTest, TestAddOccurrence) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");
  const USR TEST_BAD_USR("c#bar#");
  const IndexSourceLocation LOC_START = 12;
  const IndexSourceLocation LOC_END = 23;

  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));

    IndexFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    // Make sure everything can be read from already opened index.
    auto FileGet = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(FileGet);
    ASSERT_NE(FileGet->getRecord(), 0);
    auto Occurrence = FileGet->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_FALSE(FileGet->getFirstIncludedBy());
    ASSERT_FALSE(FileGet->getFirstInclusion());

    ASSERT_FALSE(Index.getFile(TEST_USR.str()));
    ASSERT_TRUE(Index.getDefinitions(StringRef(TEST_FILE_PATH)).empty());
  }

  // Make sure everything can be read reopening the index.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto File = Index.getFile(TEST_FILE_PATH);
    ASSERT_TRUE(File);
    ASSERT_NE(File->getRecord(), 0);
    auto Occurrence = File->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_FALSE(File->getFirstIncludedBy());
    ASSERT_FALSE(File->getFirstInclusion());

    ASSERT_FALSE(Index.getFile(TEST_USR.str()));
    ASSERT_TRUE(Index.getDefinitions(StringRef(TEST_FILE_PATH)).empty());
  }
}

TEST_F(ClangdIndexFileTest, TestOnChange) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  //TODO: check if this is similar to a usr
  const USR TEST_USR("c#foo#");
  const IndexSourceLocation LOC_START = 12;
  const IndexSourceLocation LOC_END = 23;

  // Very simple case. No occurrence in the file.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    Index.addFile(*IndexFile);

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getSymbols(TEST_USR).empty());
    IndexFile->onChange();

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getSymbols(TEST_USR).empty());
  }
  llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);

  // Simple case. Symbol with only one occurrence in one file.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));

    IndexFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);
    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);

    ASSERT_TRUE(IndexFile->getFirstOccurrence());
    ASSERT_FALSE(Index.getSymbols(TEST_USR).empty());
    IndexFile->onChange();

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getSymbols(TEST_USR).empty());
  }
  llvm::sys::fs::remove_directories(STORAGE_FILE_NAME);

  // Symbol with a reference in one file and a definition in another file.
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    auto IndexHeaderFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH + ".h", Index);
    auto IndexSymbol = llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), TEST_USR, "foo", "myns", index::SymbolKind::Function, Index);

    // Add definition
    auto IndexOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexHeaderFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Definition));
    IndexHeaderFile->addOccurrence(*IndexOccurrence);
    IndexSymbol->addOccurrence(*IndexOccurrence);

    // Add reference
    auto IndexReferenceOccurrence = llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
        *IndexFile, *IndexSymbol, LOC_START, LOC_END,
        static_cast<index::SymbolRoleSet>(index::SymbolRole::Reference));
    IndexFile->addOccurrence(*IndexReferenceOccurrence);
    IndexSymbol->addOccurrence(*IndexReferenceOccurrence);

    Index.addSymbol(*IndexSymbol);
    Index.addFile(*IndexFile);
    Index.addFile(*IndexHeaderFile);

    ASSERT_TRUE(IndexFile->getFirstOccurrence());
    ASSERT_EQ(Index.getSymbols(TEST_USR).size(), 1u);
    ASSERT_EQ(Index.getDefinitions(TEST_USR).size(), 1u);
    ASSERT_EQ(Index.getReferences(TEST_USR).size(), 2u);

    IndexFile->onChange();

    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_TRUE(IndexHeaderFile->getFirstOccurrence());
    ASSERT_EQ(Index.getDefinitions(TEST_USR).size(), 1u);
    auto Symbols = Index.getSymbols(TEST_USR);
    ASSERT_EQ(Symbols.size(), 1u);
    auto Symbol = std::move(Symbols[0]);
    auto Occurrence = Symbol->getFirstOccurrence();
    ASSERT_TRUE(Occurrence);
    ASSERT_FALSE(Occurrence->getNextInFile());
    ASSERT_FALSE(Occurrence->getNextOccurrence());
    ASSERT_EQ(Index.getReferences(TEST_USR).size(), 1u);

    IndexHeaderFile->onChange();
    ASSERT_FALSE(IndexFile->getFirstOccurrence());
    ASSERT_FALSE(IndexHeaderFile->getFirstOccurrence());
    ASSERT_TRUE(Index.getDefinitions(TEST_USR).empty());
    ASSERT_TRUE(Index.getReferences(TEST_USR).empty());
  }
}

class ClangdIndexTest : public ::testing::Test {
  virtual void SetUp() override {
    deleteStorageFileIfExists();
  }
  virtual void TearDown() override {
    deleteStorageFileIfExists();
  }
};

TEST_F(ClangdIndexTest, TestCreate) {
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    ASSERT_TRUE (llvm::sys::fs::exists(STORAGE_FILE_NAME));
  }

  uint64_t FileSizeResult;
  ASSERT_EQ(llvm::sys::fs::file_size(STORAGE_FILE_NAME, FileSizeResult),
      std::error_code());
  ASSERT_NE(FileSizeResult, 0u);
}

TEST_F(ClangdIndexTest, TestAddGetFile) {
  const std::string TEST_FILE_PATH = "/foo.cpp";
  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    Index.getStorage().startWrite();
    auto IndexFile = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), TEST_FILE_PATH, Index);
    Index.addFile(*IndexFile);
    ASSERT_TRUE(Index.getFile(TEST_FILE_PATH));
    ASSERT_FALSE(Index.getFile("/bar.cpp"));
    Index.getStorage().endWrite();
  }

  {
    ClangdIndex Index(STORAGE_FILE_NAME);
    ASSERT_TRUE(Index.getFile(TEST_FILE_PATH));
    ASSERT_FALSE(Index.getFile("/bar.cpp"));
  }
}

} // namespace clangd
} // namespace clang
