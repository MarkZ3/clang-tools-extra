//===--- Protocol.h - Language Server Protocol Implementation ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains structs based on the LSP specification at
// https://github.com/Microsoft/language-server-protocol/blob/master/protocol.md
//
// This is not meant to be a complete implementation, new interfaces are added
// when they're needed.
//
// Each struct has a toJSON and fromJSON function, that converts between
// the struct and a JSON representation. (See JSONExpr.h)
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANGD_PROTOCOL_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANGD_PROTOCOL_H

#include "JSONExpr.h"
#include "llvm/ADT/Optional.h"
#include <string>
#include <vector>

namespace clang {
namespace clangd {

enum class ErrorCode {
  // Defined by JSON RPC.
  ParseError = -32700,
  InvalidRequest = -32600,
  MethodNotFound = -32601,
  InvalidParams = -32602,
  InternalError = -32603,

  ServerNotInitialized = -32002,
  UnknownErrorCode = -32001,

  // Defined by the protocol.
  RequestCancelled = -32800,
};

struct URI {
  std::string uri;
  std::string file;

  static URI fromUri(llvm::StringRef uri);
  static URI fromFile(llvm::StringRef file);

  friend bool operator==(const URI &LHS, const URI &RHS) {
    return LHS.uri == RHS.uri;
  }

  friend bool operator!=(const URI &LHS, const URI &RHS) {
    return !(LHS == RHS);
  }

  friend bool operator<(const URI &LHS, const URI &RHS) {
    return LHS.uri < RHS.uri;
  }
};
json::Expr toJSON(const URI &U);
bool fromJSON(const json::Expr &, URI &);

struct TextDocumentIdentifier {
  /// The text document's URI.
  URI uri;
};
bool fromJSON(const json::Expr &, TextDocumentIdentifier &);

struct Position {
  /// Line position in a document (zero-based).
  int line;

  /// Character offset on a line in a document (zero-based).
  int character;

  friend bool operator==(const Position &LHS, const Position &RHS) {
    return std::tie(LHS.line, LHS.character) ==
           std::tie(RHS.line, RHS.character);
  }
  friend bool operator<(const Position &LHS, const Position &RHS) {
    return std::tie(LHS.line, LHS.character) <
           std::tie(RHS.line, RHS.character);
  }
};
bool fromJSON(const json::Expr &, Position &);
json::Expr toJSON(const Position &);

struct Range {
  /// The range's start position.
  Position start;

  /// The range's end position.
  Position end;

  friend bool operator==(const Range &LHS, const Range &RHS) {
    return std::tie(LHS.start, LHS.end) == std::tie(RHS.start, RHS.end);
  }
  friend bool operator<(const Range &LHS, const Range &RHS) {
    return std::tie(LHS.start, LHS.end) < std::tie(RHS.start, RHS.end);
  }
};
bool fromJSON(const json::Expr &, Range &);
json::Expr toJSON(const Range &);

struct Location {
  /// The text document's URI.
  URI uri;
  Range range;

  friend bool operator==(const Location &LHS, const Location &RHS) {
    return LHS.uri == RHS.uri && LHS.range == RHS.range;
  }

  friend bool operator!=(const Location &LHS, const Location &RHS) {
    return !(LHS == RHS);
  }

  friend bool operator<(const Location &LHS, const Location &RHS) {
    return std::tie(LHS.uri, LHS.range) < std::tie(RHS.uri, RHS.range);
  }
};
json::Expr toJSON(const Location &);

struct Metadata {
  std::vector<std::string> extraFlags;
};
bool fromJSON(const json::Expr &, Metadata &);

struct Command {
  /// Title of the command, like 'save'
  std::string title;

  /// The identifier of the actual command handler
  std::string command;

  /// Arguments taht the command handler should be invoked with.
  std::vector<std::string> arguments;
};
json::Expr toJSON(const Command &);

struct TextEdit {
  /// The range of the text document to be manipulated. To insert
  /// text into a document create a range where start === end.
  Range range;

  /// The string to be inserted. For delete operations use an
  /// empty string.
  std::string newText;
};
bool fromJSON(const json::Expr &, TextEdit &);
json::Expr toJSON(const TextEdit &);

struct TextDocumentItem {
  /// The text document's URI.
  URI uri;

  /// The text document's language identifier.
  std::string languageId;

  /// The version number of this document (it will strictly increase after each
  int version;

  /// The content of the opened text document.
  std::string text;
};
bool fromJSON(const json::Expr &, TextDocumentItem &);

enum class TraceLevel {
  Off = 0,
  Messages = 1,
  Verbose = 2,
};
bool fromJSON(const json::Expr &E, TraceLevel &Out);

/// Clangd extension to manage a workspace/didChangeConfiguration notification
/// since the data received is described as 'any' type in LSP.
struct CodeLensData {
  llvm::Optional<std::string> tempData;
};
bool fromJSON(const json::Expr &, CodeLensData &);
json::Expr toJSON(const CodeLensData &);

struct NoParams {};
inline bool fromJSON(const json::Expr &, NoParams &) { return true; }
using ShutdownParams = NoParams;
using ExitParams = NoParams;

/// Clangd extension to manage a workspace/didChangeConfiguration notification
/// since the data received is described as 'any' type in LSP.
struct ClangdConfigurationParamsChange {

  llvm::Optional<std::vector<std::string>> ExclusionList;
};
bool fromJSON(const json::Expr &, ClangdConfigurationParamsChange &);

struct DidChangeConfigurationParams {
  DidChangeConfigurationParams() = default;
  DidChangeConfigurationParams(ClangdConfigurationParamsChange settings)
      : settings(settings) {}

  // We use this predefined struct because it is easier to use
  // than the protocol specified type of 'any'.
  ClangdConfigurationParamsChange settings;
};
bool fromJSON(const json::Expr &, DidChangeConfigurationParams &);
json::Expr toJSON(const DidChangeConfigurationParams &);

struct InitializeParams {
  /// The process Id of the parent process that started
  /// the server. Is null if the process has not been started by another
  /// process. If the parent process is not alive then the server should exit
  /// (see exit notification) its process.
  llvm::Optional<int> processId;

  /// The rootPath of the workspace. Is null
  /// if no folder is open.
  ///
  /// @deprecated in favour of rootUri.
  llvm::Optional<std::string> rootPath;

  /// The rootUri of the workspace. Is null if no
  /// folder is open. If both `rootPath` and `rootUri` are set
  /// `rootUri` wins.
  llvm::Optional<URI> rootUri;

  /// User provided initialization options.
  llvm::Optional<std::vector<std::string>> initializationOptions;

  /// The capabilities provided by the client (editor or tool)
  /// Note: Not currently used by clangd
  // ClientCapabilities capabilities;

  /// The initial trace setting. If omitted trace is disabled ('off').
  llvm::Optional<TraceLevel> trace;
};
bool fromJSON(const json::Expr &, InitializeParams &);

struct DidOpenTextDocumentParams {
  /// The document that was opened.
  TextDocumentItem textDocument;

  /// Extension storing per-file metadata, such as compilation flags.
  llvm::Optional<Metadata> metadata;
};
bool fromJSON(const json::Expr &, DidOpenTextDocumentParams &);

struct DidCloseTextDocumentParams {
  /// The document that was closed.
  TextDocumentIdentifier textDocument;
};
bool fromJSON(const json::Expr &, DidCloseTextDocumentParams &);

struct DidSaveTextDocumentParams {
  /// The document that was closed.
  TextDocumentIdentifier textDocument;
};
bool fromJSON(const json::Expr &, DidSaveTextDocumentParams &);

struct TextDocumentContentChangeEvent {
  /// The new text of the document.
  std::string text;
};
bool fromJSON(const json::Expr &, TextDocumentContentChangeEvent &);

struct DidChangeTextDocumentParams {
  /// The document that did change. The version number points
  /// to the version after all provided content changes have
  /// been applied.
  TextDocumentIdentifier textDocument;

  /// The actual content changes.
  std::vector<TextDocumentContentChangeEvent> contentChanges;
};
bool fromJSON(const json::Expr &, DidChangeTextDocumentParams &);

enum class FileChangeType {
  /// The file got created.
  Created = 1,
  /// The file got changed.
  Changed = 2,
  /// The file got deleted.
  Deleted = 3
};
bool fromJSON(const json::Expr &E, FileChangeType &Out);

struct FileEvent {
  /// The file's URI.
  URI uri;
  /// The change type.
  FileChangeType type;
};
bool fromJSON(const json::Expr &, FileEvent &);

struct DidChangeWatchedFilesParams {
  /// The actual file events.
  std::vector<FileEvent> changes;
};
bool fromJSON(const json::Expr &, DidChangeWatchedFilesParams &);

struct FormattingOptions {
  /// Size of a tab in spaces.
  int tabSize;

  /// Prefer spaces over tabs.
  bool insertSpaces;
};
bool fromJSON(const json::Expr &, FormattingOptions &);
json::Expr toJSON(const FormattingOptions &);

struct DocumentRangeFormattingParams {
  /// The document to format.
  TextDocumentIdentifier textDocument;

  /// The range to format
  Range range;

  /// The format options
  FormattingOptions options;
};
bool fromJSON(const json::Expr &, DocumentRangeFormattingParams &);

struct DocumentOnTypeFormattingParams {
  /// The document to format.
  TextDocumentIdentifier textDocument;

  /// The position at which this request was sent.
  Position position;

  /// The character that has been typed.
  std::string ch;

  /// The format options.
  FormattingOptions options;
};
bool fromJSON(const json::Expr &, DocumentOnTypeFormattingParams &);

struct DocumentFormattingParams {
  /// The document to format.
  TextDocumentIdentifier textDocument;

  /// The format options
  FormattingOptions options;
};
bool fromJSON(const json::Expr &, DocumentFormattingParams &);

struct Diagnostic {
  /// The range at which the message applies.
  Range range;

  /// The diagnostic's severity. Can be omitted. If omitted it is up to the
  /// client to interpret diagnostics as error, warning, info or hint.
  int severity;

  /// The diagnostic's code. Can be omitted.
  /// Note: Not currently used by clangd
  // std::string code;

  /// A human-readable string describing the source of this
  /// diagnostic, e.g. 'typescript' or 'super lint'.
  /// Note: Not currently used by clangd
  // std::string source;

  /// The diagnostic's message.
  std::string message;

  friend bool operator==(const Diagnostic &LHS, const Diagnostic &RHS) {
    return std::tie(LHS.range, LHS.severity, LHS.message) ==
           std::tie(RHS.range, RHS.severity, RHS.message);
  }
  friend bool operator<(const Diagnostic &LHS, const Diagnostic &RHS) {
    return std::tie(LHS.range, LHS.severity, LHS.message) <
           std::tie(RHS.range, RHS.severity, RHS.message);
  }
};
bool fromJSON(const json::Expr &, Diagnostic &);

struct CodeActionContext {
  /// An array of diagnostics.
  std::vector<Diagnostic> diagnostics;
};
bool fromJSON(const json::Expr &, CodeActionContext &);

struct CodeActionParams {
  /// The document in which the command was invoked.
  TextDocumentIdentifier textDocument;

  /// The range for which the command was invoked.
  Range range;

  /// Context carrying additional information.
  CodeActionContext context;
};
bool fromJSON(const json::Expr &, CodeActionParams &);

struct WorkspaceEdit {
  /// Holds changes to existing resources.
  llvm::Optional<std::map<std::string, std::vector<TextEdit>>> changes;

  /// Note: "documentChanges" is not currently used because currently there is
  /// no support for versioned edits.
};
bool fromJSON(const json::Expr &, WorkspaceEdit &);
json::Expr toJSON(const WorkspaceEdit &WE);

/// Exact commands are not specified in the protocol so we define the
/// ones supported by Clangd here. The protocol specifies the command arguments
/// to be "any[]" but to make this safer and more manageable, each command we
/// handle maps to a certain llvm::Optional of some struct to contain its
/// arguments. Different commands could reuse the same llvm::Optional as
/// arguments but a command that needs different arguments would simply add a
/// new llvm::Optional and not use any other ones. In practice this means only
/// one argument type will be parsed and set.
struct ExecuteCommandParams {
  // Command to apply fix-its. Uses WorkspaceEdit as argument.
  const static std::string CLANGD_APPLY_FIX_COMMAND;
  const static std::string CLANGD_REINDEX_COMMAND;
  const static std::string CLANGD_DUMPINCLUDEDBY_COMMAND;
  const static std::string CLANGD_DUMPINCLUSIONS_COMMAND;
  const static std::string CLANGD_PRINTSTATS_COMMAND;

  /// The command identifier, e.g. CLANGD_APPLY_FIX_COMMAND
  std::string command;

  // Arguments
  llvm::Optional<WorkspaceEdit> workspaceEdit;

  llvm::Optional<TextDocumentIdentifier> textDocument;
};
bool fromJSON(const json::Expr &, ExecuteCommandParams &);
bool toJSON(const ExecuteCommandParams &);

/// A code lens represents a command that should be shown along with
/// source text, like the number of references, a way to run tests, etc.
/// A code lens is _unresolved_ when no command is associated to it. For performance
/// reasons the creation of a code lens and resolving should be done in two stages.

struct CodeLens {

  /// The range in which this code lens is valid. Should only span a single line.
  Range range;

  /// The command this code lens represents.
  llvm::Optional<Command> command;

  /// A data entry field that is preserved on a code lens item between a code lens and a code lens resolve request.
  llvm::Optional<CodeLensData> data;

};
json::Expr toJSON(const CodeLens &DH);

/// A symbol kind.
enum class SymbolKind {
  File = 1,
  Module = 2,
  Namespace = 3,
  Package = 4,
  Class = 5,
  Method = 6,
  Property = 7,
  Field = 8,
  Constructor = 9,
  Enum = 10,
  Interface = 11,
  Function = 12,
  Variable = 13,
  Constant = 14,
  String = 15,
  Number = 16,
  Boolean = 17,
  Array = 18,
  Object = 19,
  Key = 20,
  Null = 21,
  EnumMember = 22,
  Struct = 23,
  Event = 24,
  Operator = 25,
  TypeParameter = 26
};

/// Represents information about programming constructs like variables, classes,
/// interfaces etc.
struct SymbolInformation {
  /// The name of this symbol.
  std::string name;

  /// The kind of this symbol.
  SymbolKind kind;

  /// The location of this symbol.
  Location location;

  /// The name of the symbol containing this symbol.
  std::string containerName;
};
json::Expr toJSON(const SymbolInformation &);

/// The parameters of a Workspace Symbol Request.
struct WorkspaceSymbolParams {
  /// A non-empty query string
  std::string query;
};
bool fromJSON(const json::Expr &, WorkspaceSymbolParams &);

struct ApplyWorkspaceEditParams {
  WorkspaceEdit edit;
};
json::Expr toJSON(const ApplyWorkspaceEditParams &);

struct TextDocumentPositionParams {
  /// The text document.
  TextDocumentIdentifier textDocument;

  /// The position inside the text document.
  Position position;
};
bool fromJSON(const json::Expr &, TextDocumentPositionParams &);

struct ReferenceContext {
  /// Include the declaration of the current symbol.
  bool includeDeclaration;
};
bool fromJSON(const json::Expr &Params, ReferenceContext &R);

struct ReferenceParams : public TextDocumentPositionParams {
  ReferenceContext context;
};
bool fromJSON(const json::Expr &Params, ReferenceParams &R);

struct CodeLensParams {
  /// The document to request code lens for.
  TextDocumentIdentifier textDocument;
};
bool fromJSON(const json::Expr &, CodeLensParams &);


/// The kind of a completion entry.
enum class CompletionItemKind {
  Missing = 0,
  Text = 1,
  Method = 2,
  Function = 3,
  Constructor = 4,
  Field = 5,
  Variable = 6,
  Class = 7,
  Interface = 8,
  Module = 9,
  Property = 10,
  Unit = 11,
  Value = 12,
  Enum = 13,
  Keyword = 14,
  Snippet = 15,
  Color = 16,
  File = 17,
  Reference = 18,
};

/// Defines whether the insert text in a completion item should be interpreted
/// as plain text or a snippet.
enum class InsertTextFormat {
  Missing = 0,
  /// The primary text to be inserted is treated as a plain string.
  PlainText = 1,
  /// The primary text to be inserted is treated as a snippet.
  ///
  /// A snippet can define tab stops and placeholders with `$1`, `$2`
  /// and `${3:foo}`. `$0` defines the final tab stop, it defaults to the end
  /// of the snippet. Placeholders with equal identifiers are linked, that is
  /// typing in one will update others too.
  ///
  /// See also:
  /// https//github.com/Microsoft/vscode/blob/master/src/vs/editor/contrib/snippet/common/snippet.md
  Snippet = 2,
};

struct CompletionItem {
  /// The label of this completion item. By default also the text that is
  /// inserted when selecting this completion.
  std::string label;

  /// The kind of this completion item. Based of the kind an icon is chosen by
  /// the editor.
  CompletionItemKind kind = CompletionItemKind::Missing;

  /// A human-readable string with additional information about this item, like
  /// type or symbol information.
  std::string detail;

  /// A human-readable string that represents a doc-comment.
  std::string documentation;

  /// A string that should be used when comparing this item with other items.
  /// When `falsy` the label is used.
  std::string sortText;

  /// A string that should be used when filtering a set of completion items.
  /// When `falsy` the label is used.
  std::string filterText;

  /// A string that should be inserted to a document when selecting this
  /// completion. When `falsy` the label is used.
  std::string insertText;

  /// The format of the insert text. The format applies to both the `insertText`
  /// property and the `newText` property of a provided `textEdit`.
  InsertTextFormat insertTextFormat = InsertTextFormat::Missing;

  /// An edit which is applied to a document when selecting this completion.
  /// When an edit is provided `insertText` is ignored.
  ///
  /// Note: The range of the edit must be a single line range and it must
  /// contain the position at which completion has been requested.
  llvm::Optional<TextEdit> textEdit;

  /// An optional array of additional text edits that are applied when selecting
  /// this completion. Edits must not overlap with the main edit nor with
  /// themselves.
  std::vector<TextEdit> additionalTextEdits;

  // TODO(krasimir): The following optional fields defined by the language
  // server protocol are unsupported:
  //
  // command?: Command - An optional command that is executed *after* inserting
  //                     this completion.
  //
  // data?: any - A data entry field that is preserved on a completion item
  //              between a completion and a completion resolve request.
};
json::Expr toJSON(const CompletionItem &);

bool operator<(const CompletionItem &, const CompletionItem &);

/// Represents a collection of completion items to be presented in the editor.
struct CompletionList {
  /// The list is not complete. Further typing should result in recomputing the
  /// list.
  bool isIncomplete = false;

  /// The completion items.
  std::vector<CompletionItem> items;
};
json::Expr toJSON(const CompletionList &);

/// A single parameter of a particular signature.
struct ParameterInformation {

  /// The label of this parameter. Mandatory.
  std::string label;

  /// The documentation of this parameter. Optional.
  std::string documentation;
};
json::Expr toJSON(const ParameterInformation &);

/// Represents the signature of something callable.
struct SignatureInformation {

  /// The label of this signature. Mandatory.
  std::string label;

  /// The documentation of this signature. Optional.
  std::string documentation;

  /// The parameters of this signature.
  std::vector<ParameterInformation> parameters;
};
json::Expr toJSON(const SignatureInformation &);

/// Represents the signature of a callable.
struct SignatureHelp {

  /// The resulting signatures.
  std::vector<SignatureInformation> signatures;

  /// The active signature.
  int activeSignature = 0;

  /// The active parameter of the active signature.
  int activeParameter = 0;
};
json::Expr toJSON(const SignatureHelp &);

struct RenameParams {
  /// The document that was opened.
  TextDocumentIdentifier textDocument;

  /// The position at which this request was sent.
  Position position;

  /// The new name of the symbol.
  std::string newName;
};
bool fromJSON(const json::Expr &, RenameParams &);

enum class DocumentHighlightKind { Text = 1, Read = 2, Write = 3 };

/// A document highlight is a range inside a text document which deserves
/// special attention. Usually a document highlight is visualized by changing
/// the background color of its range.

struct DocumentHighlight {

  /// The range this highlight applies to.

  Range range;

  /// The highlight kind, default is DocumentHighlightKind.Text.

  DocumentHighlightKind kind = DocumentHighlightKind::Text;

  friend bool operator<(const DocumentHighlight &LHS,
                        const DocumentHighlight &RHS) {
    int LHSKind = static_cast<int>(LHS.kind);
    int RHSKind = static_cast<int>(RHS.kind);
    return std::tie(LHS.range, LHSKind) < std::tie(RHS.range, RHSKind);
  }

  friend bool operator==(const DocumentHighlight &LHS,
                         const DocumentHighlight &RHS) {
    return LHS.kind == RHS.kind && LHS.range == RHS.range;
  }
};
json::Expr toJSON(const DocumentHighlight &DH);

} // namespace clangd
} // namespace clang

#endif
