//===--- BTree.h - BTree for data stored in index -------------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANGD_INDEX_BTREE_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANGD_INDEX_BTREE_H

#include "ClangdIndexDataStorage.h"

#include <functional>

namespace llvm {
class raw_ostream;
}

namespace clang {
namespace clangd {

class BTreeVisitor {
public:
  virtual int compare(RecordPointer Record) = 0;
  virtual void visit(RecordPointer Record) = 0;
  virtual ~BTreeVisitor() {
  }
};

class BTreeComparator {
public:
  virtual int compare(RecordPointer Record1, RecordPointer Record2) = 0;
  virtual ~BTreeComparator() {
  }
};

/// A BTree implementation based on "Introduction to Algorithms". Keys are are
/// pointers to data in the index data storage.
class BTree {
public:
  BTree(ClangdIndexDataStorage &Storage, RecordPointer record,
      BTreeComparator &Comparator);
  BTree(ClangdIndexDataStorage &Storage, RecordPointer record,
      BTreeComparator &Comparator, unsigned Degree);
  void insert(RecordPointer Record);
  bool remove(RecordPointer Record);
  void accept(BTreeVisitor& Visitor);
  void dump(std::function<void(RecordPointer, llvm::raw_ostream &OS)> Func,
      llvm::raw_ostream &OS);

private:
  ClangdIndexDataStorage &Storage;
  BTreeComparator &Comparator;

  const unsigned Degree;
  const unsigned MaxNumKeys;
  const unsigned MaxNumChildren;
  const static int INVALID_CHILDREN = 0;
  const static int INVALID_KEY = 0;
  const static int KEY_OFFSET = 0;
  const int ChildrenOffset;

  RecordPointer RootNodePtr;
  RecordPointer RootNode;

  struct Node {
    BTree &Tree;
    RecordPointer NodeRec;
    ClangdIndexDataPieceRef Piece;
    Node(BTree &Tree, RecordPointer NodeRec);
    unsigned getNumKeys();
    unsigned getNumChildren();
    RecordPointer getKey(unsigned Idx);
    void putKey(unsigned Idx, RecordPointer Rec);
    RecordPointer getChild(unsigned Idx);
    void putChild(unsigned Idx, RecordPointer Rec);
    bool isFull();
    bool isLeaf();
  };

  void insertNonFull(Node &InsertedInto, RecordPointer Record);
  void search(RecordPointer SearchedNode, BTreeVisitor& Visitor);

  void readNode(RecordPointer Rec);
  RecordPointer allocateNode();
  void splitChild(RecordPointer ParentNodeRec, int SplitIndex,
      RecordPointer SplitChildNodeRec);
  void dump(std::function<void(RecordPointer, llvm::raw_ostream &OS)> Func,
      llvm::raw_ostream &OS, Node &InsertedInto, unsigned Depth);
  enum class DeleteMode {
    HIGHEST, // Delete the key with the highest value from a node
    LOWEST, // Delete the key with the lowest value from a node
    EXACT // Delete the key with the exact value from a node, if present
  };

  RecordPointer tryRemoveFromNode(RecordPointer Record, Node &RemovedFrom,
      DeleteMode Mode);
  RecordPointer deleteKeyInInternalNode(RecordPointer RemovedRecord,
      unsigned IndexInNode, Node &RemovedFrom);
  RecordPointer deleteKeyNotInInternalNode(RecordPointer RemovedRecord,
      Node &RemovedFrom, DeleteMode Mode);
  void mergeNodes(Node &LeftDestinationNode, Node &RightSourceNode,
      RecordPointer GlueKey);
  void insertKeyAtIndex(Node &RemovedFrom, unsigned Index, RecordPointer Key);
  void deleteKeyAtIndex(Node &RemovedFrom, unsigned Index);
  void makeRoot(RecordPointer SRec);
};

} /* namespace clangd */
} /* namespace clang */

#endif
