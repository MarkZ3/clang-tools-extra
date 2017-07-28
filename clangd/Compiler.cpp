//===--- Compiler.cpp -------------------------------------------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===---------------------------------------------------------------------===//
#include "Compiler.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/PreprocessorOptions.h"

namespace clang {
namespace clangd {

/// Creates a CompilerInstance from \p CI, with main buffer overriden to \p
/// Buffer and arguments to read the PCH from \p Preamble, if \p Preamble is not
/// null. Note that vfs::FileSystem inside returned instance may differ from \p
/// VFS if additional file remapping were set in command-line arguments.
/// On some errors, returns null. When non-null value is returned, it's expected
/// to be consumed by the FrontendAction as it will have a pointer to the \p
/// Buffer that will only be deleted if BeginSourceFile is called.
std::unique_ptr<CompilerInstance>
prepareCompilerInstance(std::unique_ptr<clang::CompilerInvocation> CI,
                        const PrecompiledPreamble *Preamble,
                        std::unique_ptr<llvm::MemoryBuffer> Buffer,
                        std::shared_ptr<PCHContainerOperations> PCHs,
                        IntrusiveRefCntPtr<vfs::FileSystem> VFS,
                        DiagnosticConsumer &DiagsClient) {
  assert(VFS && "VFS is null");
  assert(!CI->getPreprocessorOpts().RetainRemappedFileBuffers &&
         "Setting RetainRemappedFileBuffers to true will cause a memory leak "
         "of ContentsBuffer");

  // NOTE: we use Buffer.get() when adding remapped files, so we have to make
  // sure it will be released if no error is emitted.
  if (Preamble) {
    Preamble->AddImplicitPreamble(*CI, VFS, Buffer.get());
  } else {
    CI->getPreprocessorOpts().addRemappedFile(
        CI->getFrontendOpts().Inputs[0].getFile(), Buffer.get());
  }

  auto Clang = llvm::make_unique<CompilerInstance>(PCHs);
  Clang->setInvocation(std::move(CI));
  Clang->createDiagnostics(&DiagsClient, false);

  if (auto VFSWithRemapping = createVFSFromCompilerInvocation(
          Clang->getInvocation(), Clang->getDiagnostics(), VFS))
    VFS = VFSWithRemapping;
  Clang->setVirtualFileSystem(VFS);

  Clang->setTarget(TargetInfo::CreateTargetInfo(
      Clang->getDiagnostics(), Clang->getInvocation().TargetOpts));
  if (!Clang->hasTarget())
    return nullptr;

  // RemappedFileBuffers will handle the lifetime of the Buffer pointer,
  // release it.
  Buffer.release();
  return Clang;
}

std::unique_ptr<CompilerInvocation>
createCompilerInvocation(PathRef FileName, ArrayRef<const char *> ArgList,
                         IntrusiveRefCntPtr<DiagnosticsEngine> Diags,
                         IntrusiveRefCntPtr<vfs::FileSystem> VFS) {
  auto CI = createInvocationFromCommandLine(ArgList, std::move(Diags),
                                            std::move(VFS));

  // When dealing with opening headers, we might use the compile arguments of
  // one of the source files including it, but we still need to change the input
  // file to the header file path. Doing this here is less error prone than
  // trying to modify the command-line arguments.
  auto &Inputs = CI->getFrontendOpts().Inputs;
  // Only do the input file substitution trick when there's only one input file,
  // otherwise we might be in an entirely (unknown) different situation.
  if (Inputs.size() == 1) {
    auto &OldInput = Inputs[0];
    if (OldInput.getFile() != FileName)
      Inputs[0] = FrontendInputFile(FileName, OldInput.getKind());
  }
  return CI;
}

} // namespace clangd
} // namespace clang
