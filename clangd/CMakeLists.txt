set(LLVM_LINK_COMPONENTS
  Support
  )

set(CLANGD_ATOMIC_LIB "")
if(NOT HAVE_CXX_ATOMICS64_WITHOUT_LIB)
  list(APPEND CLANGD_ATOMIC_LIB "atomic")
endif()

if( ENABLE_LIB_INDEX_STORE )
  set(LIB_INDEX_STORE
    IndexStore
  )
  set(INDEX_STORE_SUPPORT_SOURCES
    index/indexstore/ClangdIndexStoreIndexer.cpp
  )
endif()

add_clang_library(clangDaemon
  AST.cpp
  ClangdFileUtils.cpp
  ClangdLSPServer.cpp
  ClangdServer.cpp
  ClangdUnit.cpp
  CodeComplete.cpp
  CodeCompletionStrings.cpp
  Compiler.cpp
  Context.cpp
  Diagnostics.cpp
  DraftStore.cpp
  FindSymbols.cpp
  FileDistance.cpp
  FuzzyMatch.cpp
  GlobalCompilationDatabase.cpp
  Headers.cpp
  JSONRPCDispatcher.cpp
  Logger.cpp
  Protocol.cpp
  ProtocolHandlers.cpp
  Quality.cpp
  SourceCode.cpp
  Threading.cpp
  Trace.cpp
  TUScheduler.cpp
  URI.cpp
  XRefs.cpp
  index/CanonicalIncludes.cpp
  index/FileIndex.cpp
  index/BTree.cpp
  index/ClangdIndex.cpp
  index/ClangdIndexerImpl.cpp
  index/ClangdIndexDataPiece.cpp
  index/ClangdIndexDataStorage.cpp
  index/ClangdIndexString.cpp
  index/Index.cpp
  index/MemIndex.cpp
  index/Merge.cpp
  index/SymbolCollector.cpp
  index/SymbolYAML.cpp
  ${INDEX_STORE_SUPPORT_SOURCES}

  LINK_LIBS
  clangAST
  clangASTMatchers
  clangBasic
  clangDriver
  clangFormat
  clangFrontend
  clangIndex
  clangLex
  clangSema
  clangSerialization
  clangTooling
  clangToolingCore
  clangToolingInclusions
  clangToolingRefactor
  ${LLVM_PTHREAD_LIB}
  ${CLANGD_ATOMIC_LIB}
  ${LIB_INDEX_STORE}
  )

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/clangd-config.h)

if( LLVM_LIB_FUZZING_ENGINE OR LLVM_USE_SANITIZE_COVERAGE )
  add_subdirectory(fuzzer)
endif()
add_subdirectory(tool)
add_subdirectory(global-symbol-builder)
