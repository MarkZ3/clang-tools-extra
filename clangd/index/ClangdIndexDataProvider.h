#ifndef TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATAPROVIDER_H_
#define TOOLS_CLANG_TOOLS_EXTRA_CLANGD_INDEX_CLANGDINDEXDATAPROVIDER_H_

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"

#include "clang/Index/IndexSymbol.h"

#include <memory>

namespace clang {

class SourceManager;

namespace clangd {

using USR = llvm::SmallString<256>;

class ClangdIndexDataOccurrence;

class ClangdIndexDataSymbol {
public:
  virtual index::SymbolKind getKind() = 0;
  /// For example, for mynamespace::myclass::mymethod, this will be
  /// mymethod.
  virtual std::string getName() = 0;
  /// For example, for mynamespace::myclass::mymethod, this will be
  /// mynamespace::myclass::
  virtual std::string getQualifier() = 0;
  virtual std::string getUsr() = 0;

  virtual void foreachOccurrence(llvm::Optional<index::SymbolRoleSet> RolesFilter, llvm::function_ref<bool(ClangdIndexDataOccurrence&)> Receiver) = 0;

  virtual ~ClangdIndexDataSymbol() = default;
};

class ClangdIndexDataOccurrence {
public:
  enum class OccurrenceType : uint16_t {
     OCCURRENCE,
     DEFINITION_OCCURRENCE
   };

  virtual OccurrenceType getKind() const { return OccurrenceType::OCCURRENCE; }
  virtual std::string getPath() = 0;
  /// Get the start offset of the symbol occurrence. The SourceManager can be
  /// used for implementations that need to convert from a line/column
  /// representation to an offset.
  virtual uint32_t getStartOffset(SourceManager &SM) = 0;
  /// Get the end offset of the symbol occurrence. The SourceManager can be
  /// used for implementations that need to convert from a line/column
  /// representation to an offset.
  virtual uint32_t getEndOffset(SourceManager &SM) = 0;
  virtual ~ClangdIndexDataOccurrence() = default;

  static bool classof(const ClangdIndexDataOccurrence *O) { return O->getKind() == OccurrenceType::OCCURRENCE; }
};

/// An occurrence that also has definition with a body that requires additional
/// locations to keep track of the beginning and end of the body.
class ClangdIndexDataDefinitionOccurrence : public ClangdIndexDataOccurrence {
public:
  virtual uint32_t getDefStartOffset(SourceManager &SM) = 0;
  virtual uint32_t getDefEndOffset(SourceManager &SM) = 0;

  static bool classof(const ClangdIndexDataOccurrence *O) { return O->getKind() == OccurrenceType::DEFINITION_OCCURRENCE; }
};

class ClangdIndexDataProvider {
public:

  virtual void foreachSymbols(StringRef Query, llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) = 0;
  virtual void foreachSymbols(const USR &Usr, llvm::function_ref<bool(ClangdIndexDataSymbol&)> Receiver) = 0;

  //FIXME: For debugging...for now.
  virtual void dumpIncludedBy(StringRef File) {}
  virtual void dumpInclusions(StringRef File) {}

  virtual ~ClangdIndexDataProvider() = default;
};

} // namespace clangd
} // namespace clang

#endif
