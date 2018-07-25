include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

add_clang_tool(clangd
  ClangdMain.cpp
  )

set(LLVM_LINK_COMPONENTS
  support
  )

if( ENABLE_LIB_INDEX_STORE )
  set(LIB_INDEX_STORE
    IndexStore
  )
endif()

target_link_libraries(clangd
  PRIVATE
  clangBasic
  clangDaemon
  clangFormat
  clangFrontend
  clangSema
  clangTooling
  clangToolingCore
  ${LIB_INDEX_STORE}
  )
