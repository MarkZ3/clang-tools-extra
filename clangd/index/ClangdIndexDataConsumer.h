//===--- ClangdIndexDataConsumer.h - Consumes index data for Clangd index--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANGD_CLANGDINDEXDATACONSUMER_H_
#define LLVM_CLANG_TOOLS_EXTRA_CLANGD_CLANGDINDEXDATACONSUMER_H_

#include "llvm/Support/Format.h"
#include "llvm/Support/FormatVariadic.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Index/CodegenNameGenerator.h"
#include "clang/Index/IndexDataConsumer.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Lex/Lexer.h"
#include "index/ClangdIndex.h"

#include <unordered_map>

namespace clang {
namespace clangd{

namespace {
IndexSourceLocation createIndexSourceLocation(SourceLocation Loc, const SourceManager& SourceMgr, const LangOptions& LangOpts) {
  unsigned Offset = SourceMgr.getFileOffset(SourceMgr.getSpellingLoc(Loc));
  if (Offset > UINT32_MAX) {
    //FIXME is uint32_t considered not big enough??
    llvm::errs() << "Offset too big to fit in uint32_t" << "\n";
  }
  uint32_t Offset32 = Offset;
  return IndexSourceLocation(Offset32);
}

std::string getName(const Decl *D) {
  auto ND = dyn_cast<NamedDecl>(D);
  if (!ND)
    return {};

  return ND->getNameAsString();
}

std::string getQualifier(const Decl *D, const LangOptions &LangOpts) {
  auto ND = dyn_cast<NamedDecl>(D);
  if (!ND)
    return {};

  // Get the full qualified name, the non-qualified name and then diff
  // them. If there's something left, that's the qualifier.
  // The extra "::" is also trimmed.
  std::string Res;
  PrintingPolicy WithScopePP(LangOpts);
  std::string WithScopeBuf;
  llvm::raw_string_ostream WithScopeOS(WithScopeBuf);
  ND->printQualifiedName(WithScopeOS, WithScopePP);

  std::string ResWithScope = WithScopeOS.str();
  if (!ResWithScope.empty()) {
    // Get non-qualified name
    std::string PrintedNameBuf;
    llvm::raw_string_ostream PrintedNameOS(PrintedNameBuf);
    ND->printName(PrintedNameOS);
    auto Last = ResWithScope.rfind(PrintedNameOS.str());
    if (Last != std::string::npos) {
      Res = ResWithScope.substr(0, Last);
      if (Res.length() > 2 &&
          Res.substr(Res.length() - 2, Res.length()) == "::")
        Res = Res.substr(0, Res.length() - 2);
    }
  }
  return Res;
}

}

/// This only consumes declarations, definitions and references at the moment.
class ClangdIndexDataConsumer : public index::IndexDataConsumer {
  std::unique_ptr<index::CodegenNameGenerator> CGNameGen;
  ClangdIndex &Index;
  ClangdIndexFile &IndexFile;
  std::string MainFilePath;
  std::set<FileID> FilesBeingIndexed;
  std::set<std::string> FilePathsBeingIndexed;
  SourceManager *SM;

  std::unordered_map<std::string, RecordPointer> IndexFileCache;
  std::unordered_map<std::string, RecordPointer> IndexSymbolCache;

  std::unique_ptr<ClangdIndexFile> getOrCreateIndexFile(const SourceManager &SM, FileID FID) {
    const FileEntry *F = SM.getFileEntryForID(FID);
    if (!F)
      return {};

    StringRef FilePath = F->tryGetRealPathName();
    if (FilePath.empty()) {
      llvm::errs()
          << llvm::format("File Path empty. Indexing %s",
              IndexFile.getPath().c_str()) << "\n";
      return {};
    }

    auto FileCacheIt = IndexFileCache.find(FilePath);
    if (FileCacheIt != IndexFileCache.end()) {
      return llvm::make_unique<ClangdIndexFile>(Index.getStorage(), FileCacheIt->second, Index);
    }

    auto File = Index.getFile(FilePath);
    if (!File) {
      File = llvm::make_unique<ClangdIndexFile>(Index.getStorage(), FilePath, Index);
      Index.addFile(*File);
    }
    IndexFileCache.insert( { FilePath, File->getRecord() });
    return File;
  }

  llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> getOrCreateSymbols(
      const USR& Buf, StringRef Name, index::SymbolKind Kind, StringRef Qualifier) {
    llvm::SmallVector<std::unique_ptr<ClangdIndexSymbol>, 1> Result;
    std::string USRStr = Buf.str();
    auto SymbolCacheIt = IndexSymbolCache.find(USRStr);
    if (SymbolCacheIt != IndexSymbolCache.end()) {
      Result.push_back(llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), SymbolCacheIt->second, Index));
      return Result;
    }

    Result = Index.getSymbols(Buf);
    if (Result.empty()) {
      Result.push_back(llvm::make_unique<ClangdIndexSymbol>(Index.getStorage(), Buf, Name, Qualifier, Kind, Index));
      Index.addSymbol(*Result.front());
    }
    IndexSymbolCache.insert( { USRStr, Result.front()->getRecord() });
    return Result;
  }

public:
  ClangdIndexDataConsumer(raw_ostream &OS, ClangdIndex &Index, ClangdIndexFile &IndexFile) :
      Index(Index), IndexFile(IndexFile), MainFilePath(IndexFile.getPath()), SM(nullptr) {
    assert(!MainFilePath.empty());
  }

  void initialize(ASTContext &Ctx) override {
    CGNameGen.reset(new index::CodegenNameGenerator(Ctx));
    SM = &Ctx.getSourceManager();
  }

  bool handleDeclOccurence(const Decl *D, index::SymbolRoleSet Roles,
                           ArrayRef<index::SymbolRelation> Relations,
                           SourceLocation Loc,
// Hack so that we can use the same Clangd branch with Clang that might or
// might not have the libIndexStore patches
#ifdef HAS_SYS_FILE_PARAM
     bool IsInSystemFile,
#endif
                           index::IndexDataConsumer::ASTNodeInfo ASTNode) override {
    ASTContext &Ctx = D->getASTContext();

    SmallString<256> USRBuf;
    if (!index::generateUSRForDecl(D, USRBuf)) {
      SourceLocation StartLoc = Loc;
      SourceRange Range = SourceRange(StartLoc,
          Lexer::getLocForEndOfToken(StartLoc, 0, *SM, Ctx.getLangOpts()));

      FileID FID = SM->getFileID(StartLoc);
      auto OccurrenceFile = getOrCreateIndexFile(*SM, SM->getFileID(Range.getBegin()));
      if (!OccurrenceFile) {
        return true;
      }

      //This is the logic to only index a given header once. We can only
      //start indexing a file if it has no "last indexing time" set.
      //We can only resume indexing if we
      //were already indexing it before in the same consumer.
      //A file is considered to be already indexing when it has the same
      //FileID for the same file path. Since different inclusions of the
      //same file have different FileIDs, it means we only index one
      //version of a given file.
      auto FilePath = OccurrenceFile->getPath();
      assert(!FilePath.empty());
      if (FilePathsBeingIndexed.find(FilePath) == FilePathsBeingIndexed.end()) {
        if (OccurrenceFile->getLastIndexingTime()) {
          // We should at least need to index the main file. If this trips
          // this means we started indexing without clearing "last indexing time" first.
          assert(!SM->isInMainFile(Range.getBegin()));
          // File indexed, skip it.
          return true;
        }
        // First time seeing this file, start indexing it.
        FilePathsBeingIndexed.insert(FilePath);
        assert(FilesBeingIndexed.find(FID) == FilesBeingIndexed.end());
        FilesBeingIndexed.insert(FID);
      } else if (FilesBeingIndexed.find(FID) == FilesBeingIndexed.end()) {
        // File already being indexed, included a second time.
        return true;
      }

      auto Symbols = getOrCreateSymbols(USRBuf, getName(D), index::getSymbolInfo(D).Kind, getQualifier(D, Ctx.getLangOpts()));
      //FIXME: multiple symbols?
      auto Symbol = std::move(Symbols.front());
      IndexSourceLocation LocStart = createIndexSourceLocation(Range.getBegin(), *SM, Ctx.getLangOpts());
      IndexSourceLocation LocEnd = createIndexSourceLocation(Range.getEnd(), *SM, Ctx.getLangOpts());


      llvm::Optional<SourceRange> DefinitionRange;
      if (dyn_cast<FunctionDecl>(D)) {
        if (auto OrigD = dyn_cast<FunctionDecl>(ASTNode.OrigD)) {
          if (OrigD->isThisDeclarationADefinition()) {
            DefinitionRange = OrigD->getSourceRange();
          }
        }
      }

      std::unique_ptr<ClangdIndexOccurrence> Occurrence;
      if (DefinitionRange) {
        IndexSourceLocation LocDefStart = createIndexSourceLocation(DefinitionRange->getBegin(), *SM, Ctx.getLangOpts());
        IndexSourceLocation LocDefEnd = createIndexSourceLocation(DefinitionRange->getEnd(), *SM, Ctx.getLangOpts());
        Occurrence =
            llvm::make_unique<ClangdIndexDefinitionOccurrence>(Index.getStorage(), Index,
                *OccurrenceFile,
                *Symbol, LocStart, LocEnd, LocDefStart, LocDefEnd,
                static_cast<index::SymbolRoleSet>(Roles));
      } else {
        Occurrence =
            llvm::make_unique<ClangdIndexOccurrence>(Index.getStorage(), Index,
                *OccurrenceFile,
                *Symbol, LocStart, LocEnd,
                static_cast<index::SymbolRoleSet>(Roles));
      }

      Symbol->addOccurrence(*Occurrence);
      OccurrenceFile->addOccurrence(*Occurrence);
    }

    return true;
  }
};

} // namespace clangd
} // namespace clang

#endif
