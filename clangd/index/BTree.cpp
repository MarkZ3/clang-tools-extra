//===--- BTree.cpp - BTree for data stored in index -----------*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-------------------------------------------------------------------===//

#include "BTree.h"

#include "llvm/Support/raw_ostream.h"

#include <cassert>
#include <sstream>

namespace clang {
namespace clangd {

BTree::BTree(ClangdIndexDataStorage &Storage, RecordPointer Record,
    BTreeComparator &Comparator) :
    BTree(Storage, Record, Comparator, 10) {
}

BTree::BTree(ClangdIndexDataStorage &Storage, RecordPointer Record,
    BTreeComparator &Comparator, unsigned Degree) :
    Storage(Storage), Comparator(Comparator), Degree(Degree),
    MaxNumKeys(Degree * 2 - 1), MaxNumChildren(Degree * 2),
    ChildrenOffset(MaxNumKeys * ClangdIndexDataStorage::PTR_SIZE), RootNode(0) {
  assert(Degree >= 2);
  RootNodePtr = Record;
  RootNode = Storage.getRecPtr(RootNodePtr);
}

RecordPointer BTree::allocateNode() {
  return Storage.mallocRecord(
      (MaxNumKeys * 2 + 1) * ClangdIndexDataStorage::PTR_SIZE);
}

void BTree::makeRoot(RecordPointer SRec) {
  RootNode = SRec;
  Storage.putRecPtr(RootNodePtr, RootNode);
}

void BTree::insert(RecordPointer Record) {
  if (RootNode == 0) {
    RootNode = allocateNode();
    Storage.putRecPtr(RootNodePtr, RootNode);
    Node RootNodeObj (*this, RootNode);
    RootNodeObj.putKey(0, Record);
    return;
  }

  Node RootNodeObj (*this, RootNode);
  if (RootNodeObj.isFull()) {
    RecordPointer RRec = RootNode;
    RecordPointer SRec = allocateNode();
    makeRoot(SRec);
    Node NewRootNodeObj = Node(*this, RootNode);
    NewRootNodeObj.putChild(0, RRec);
    splitChild(SRec, 0, RRec);
    insertNonFull(NewRootNodeObj, Record);
  } else {
    insertNonFull(RootNodeObj, Record);
  }
}

void BTree::insertNonFull(Node &InsertedInto, RecordPointer Record) {
  int I = InsertedInto.getNumKeys() - 1;
  if (InsertedInto.isLeaf()) {
    for (; I >= 0; I--) {
      RecordPointer IKey = InsertedInto.getKey(I);
      int Comp = Comparator.compare(Record, IKey);
      if (Comp == 0) {
        llvm::errs() << "Warning: Trying to insert duplicate key in BTree: " << Record << "\n";
        return;
      }
      if (Comp >= 0) {
        break;
      }
      InsertedInto.putKey(I + 1, IKey);
    }
    InsertedInto.putKey(I + 1, Record);
  } else {
    for (; I >= 0; I--) {
      RecordPointer IKey = InsertedInto.getKey(I);
      int Comp = Comparator.compare(Record, IKey);
      if (Comp == 0) {
        llvm::errs() << "Warning: Trying to insert duplicate key in BTree: " << Record << "\n";
        return;
      }
      if (Comp >= 0) {
        break;
      }
    }
    I++;
    RecordPointer ChildRec = InsertedInto.getChild(I);
    Node ChildNode(*this, ChildRec);
    if (ChildNode.isFull()) {
      splitChild(InsertedInto.NodeRec, I, ChildRec);
      int Comp = Comparator.compare(Record, InsertedInto.getKey(I));
      if (Comp == 0) {
        llvm::errs() << "Warning: Trying to insert duplicate key in BTree: " << Record << "\n";
        return;
      }
      if (Comp > 0) {
        I++;
      }
    }
    ChildRec = InsertedInto.getChild(I);
    Node TempChildNode(*this, ChildRec);
    insertNonFull(TempChildNode, Record);
  }
}

void BTree::splitChild(RecordPointer ParentNodeRec, int SplitAtIndex,
    RecordPointer SplitChildNodeRec) {
  Node YNode(*this, SplitChildNodeRec);
  Node ZNode(*this, allocateNode());
  // Copy ~half of the keys to new node from node being split
  for (unsigned I = 0; I < Degree - 1; I++) {
    RecordPointer YKey = YNode.getKey(I + Degree);
    ZNode.putKey(I, YKey);
  }

  // Copy corresponding ~half of the children to new node from node being split
  for (unsigned I = 0; I < Degree; I++) {
    RecordPointer YChild = YNode.getChild(I + Degree);
    ZNode.putChild(I, YChild);
  }

  Node XNode(*this, ParentNodeRec);
  // Offset children by 1 in the parent node, so that there is room for the new
  // child
  for (int I = MaxNumKeys; I > SplitAtIndex; I--) {
    RecordPointer XChild = XNode.getChild(I);
    if (XChild != INVALID_CHILDREN) {
      XNode.putChild(I + 1, XChild);
    }
  }
  XNode.putChild(SplitAtIndex + 1, ZNode.NodeRec);
  // Offset keys by 1 in the parent node, so that there is room for the new key
  for (int I = MaxNumKeys - 1; I >= SplitAtIndex; I--) {
    RecordPointer XKey = XNode.getKey(I);
    if (XKey != INVALID_KEY) {
      XNode.putKey(I + 1, XKey);
    }
  }
  XNode.putKey(SplitAtIndex, YNode.getKey(Degree - 1));

  // Clear out the copied keys
  for (unsigned I = MaxNumKeys - 1; I >= Degree - 1; I--) {
    YNode.putKey(I, INVALID_KEY);
  }
  // Clear out the copied children
  for (unsigned I = MaxNumKeys; I > Degree - 1; I--) {
    YNode.putChild(I, INVALID_CHILDREN);
  }
}

bool BTree::remove(RecordPointer Record) {
  if (RootNode == 0) {
    return false;
  }
  Node RootNodeObj (*this, RootNode);
  return tryRemoveFromNode(Record, RootNodeObj, DeleteMode::EXACT) != 0;
}

RecordPointer BTree::tryRemoveFromNode(RecordPointer RemovedRecord,
    Node &RemovedFrom, DeleteMode Mode) {
  bool NodeHasKey = false;

  int I;
  switch (Mode) {
  case DeleteMode::EXACT: {
    I = RemovedFrom.getNumKeys() - 1;
    for (; I >= 0; I--) {
      RecordPointer IKey = RemovedFrom.getKey(I);
      // We use the comparator here but we could make this more strict and only
      // allow deleting with the exact recorde number, for better performance.
      if (Comparator.compare(IKey, RemovedRecord) == 0) {
        NodeHasKey = true;
        if (RemovedFrom.isLeaf()) {
          // Case 1
          deleteKeyAtIndex(RemovedFrom, I);
          return RemovedRecord;
        }
        break;
      }
    }
    break;
  }
    // Part of Case 2a
  case DeleteMode::HIGHEST: {
    if (RemovedFrom.isLeaf()) {
      RecordPointer HighestKey = RemovedFrom.getKey(RemovedFrom.getNumKeys() - 1);
      return tryRemoveFromNode(HighestKey, RemovedFrom, DeleteMode::EXACT);
    }
    break;
  }
    // Part of Case 2b
  case DeleteMode::LOWEST: {
    if (RemovedFrom.isLeaf()) {
      RecordPointer LowestKey = RemovedFrom.getKey(0);
      return tryRemoveFromNode(LowestKey, RemovedFrom, DeleteMode::EXACT);
    }
    break;
  }
  }

  if (NodeHasKey) {
    // Case 2
    assert(Mode == DeleteMode::EXACT);
    return deleteKeyInInternalNode(RemovedRecord, I, RemovedFrom);
  }

  // Case 3
  return deleteKeyNotInInternalNode(RemovedRecord, RemovedFrom, Mode);
}

/// Handles case 2a, 2b and 2c. The key was found in currently visited internal
/// node.
///
/// Case 2a: Find a key in *previous* node to replace it.
/// Case 2b: Find a key in *next* node to replace it.
/// Case 2c: Previous and next child nodes don't have enough keys to give one
/// away. Merge key and next child node into previous child node then delete
/// key.
RecordPointer BTree::deleteKeyInInternalNode(RecordPointer RemovedRecord,
    unsigned IndexInNode, Node &InternalNode) {
  RecordPointer PrevChild = InternalNode.getChild(IndexInNode);
  Node PrevChildNode(*this, PrevChild);
  unsigned PrevChildNumKeys = PrevChildNode.getNumKeys();
  if (PrevChildNumKeys >= Degree) {
    // Case 2a: Find a key in *previous* node to replace it.
    RecordPointer HighestDeleted = tryRemoveFromNode(INVALID_KEY, PrevChildNode,
        DeleteMode::HIGHEST);
    assert(HighestDeleted != INVALID_KEY);
    InternalNode.putKey(IndexInNode, HighestDeleted);
    return RemovedRecord;
  } else {
    RecordPointer NextChild = InternalNode.getChild(IndexInNode + 1);
    assert(NextChild != INVALID_CHILDREN);
    Node NextChildNode(*this, NextChild);
    if (NextChildNode.getNumKeys() >= Degree) {
      // Case 2b: Find a key in *next* node to replace it.
      RecordPointer LowestDeleted = tryRemoveFromNode(INVALID_KEY,
          NextChildNode, DeleteMode::LOWEST);
      assert(LowestDeleted != INVALID_KEY);
      InternalNode.putKey(IndexInNode, LowestDeleted);
      return RemovedRecord;
    } else {
      // Case 2c: Merge previous and next node.

      // Removing key being pushed down
      deleteKeyAtIndex(InternalNode, IndexInNode);
      mergeNodes(PrevChildNode, NextChildNode, RemovedRecord);

      // Delete right node we just copied into left
      Storage.freeRecord(NextChildNode.NodeRec);

      RecordPointer Removed = tryRemoveFromNode(RemovedRecord, PrevChildNode,
          DeleteMode::EXACT);
      Node RootNodeObj(*this, RootNode);
      if (RootNodeObj.getNumKeys() == 0) {
        makeRoot(RootNodeObj.getChild(0));
      }

      return Removed;
    }
  }

  return INVALID_KEY;
}

/// Handles case 3a and 3b. The key was not found in currently visited internal
/// node.
///
/// Case 3a: The next node to be visited doesn't contain enough keys. One of
/// the sibling nodes has enough keys to give one away. Push up the given away
/// key to current node and push down a key do next node then recurse into it.
///
/// Case 3b: The next node to be visited doesn't contain enough keys.
/// Both sibling nodes (only one in case of left-most or right-most) don't have
/// enough keys to give one away.
/// Merge key and sibling with next node then recurse into it.
///
/// If (or once) the next node to be visited has enough keys, recurse into it.
RecordPointer BTree::deleteKeyNotInInternalNode(RecordPointer RemovedRecord,
    Node &InternalNode, DeleteMode Mode) {
  unsigned I = 0;
  if (Mode == DeleteMode::EXACT) {
    for (; I < MaxNumKeys; I++) {
      RecordPointer Key = InternalNode.getKey(I);
      if (Key == INVALID_KEY) {
        break;
      }
      int Compare = Comparator.compare(Key, RemovedRecord);
      if (Compare > 0) {
        break;
      }
    }
  } else if (Mode == DeleteMode::HIGHEST) {
    I = InternalNode.getNumChildren() - 1;
  }

  RecordPointer Child = InternalNode.getChild(I);
  if (Child == INVALID_CHILDREN) {
    return INVALID_KEY;
  }

  std::shared_ptr<Node> NextRemoveFromNode = std::make_shared<Node>(*this,
      Child);
  if (NextRemoveFromNode->getNumKeys() != Degree - 1) {
    // The next node to be visited already has enough keys so just recurse into
    // it.
    return tryRemoveFromNode(RemovedRecord, *NextRemoveFromNode, Mode);
  }

  std::shared_ptr<Node> LeftSibling = I > 0 ?
          std::make_shared<Node>(*this, InternalNode.getChild(I - 1)) :
          nullptr;
  std::shared_ptr<Node> RightSibling = I < InternalNode.getNumKeys() ?
          std::make_shared<Node>(*this, InternalNode.getChild(I + 1)) :
          nullptr;

  unsigned LeftNumKeys = LeftSibling ? LeftSibling->getNumKeys() : 0;
  unsigned RightNumKeys = RightSibling ? RightSibling->getNumKeys() : 0;
  if (RightNumKeys >= Degree || LeftNumKeys >= Degree) {
    // Case 3a
    bool UseRightSibling = RightNumKeys >= Degree;
    auto SiblingNode = UseRightSibling ? RightSibling : LeftSibling;
    if (UseRightSibling) {
      // Pushing down a key from X to Cx
      unsigned WriteIndex = NextRemoveFromNode->getNumKeys();
      NextRemoveFromNode->putKey(WriteIndex, InternalNode.getKey(I));
      // Copying a key from right sibling to X
      InternalNode.putKey(I, SiblingNode->getKey(0));
      // Copying a dangling child to proper position in Cx
      NextRemoveFromNode->putChild(WriteIndex + 1, SiblingNode->getChild(0));
      // Delete Copied key from right sibling
      SiblingNode->putChild(0, SiblingNode->getChild(1));
      deleteKeyAtIndex(*SiblingNode, 0);
    } else {
      unsigned SiblingNumKeys = SiblingNode->getNumKeys();
      // Pushing down a key from X to Cx
      insertKeyAtIndex(*NextRemoveFromNode, 0, InternalNode.getKey(I - 1));
      // Copying a key from left sibling to X
      InternalNode.putKey(I - 1, SiblingNode->getKey(SiblingNumKeys - 1));
      // Copying a dangling child to proper position in Cx
      NextRemoveFromNode->putChild(0, SiblingNode->getChild(SiblingNumKeys));
      // Delete Copied key from left sibling
      deleteKeyAtIndex(*SiblingNode, SiblingNumKeys - 1);
    }
    return tryRemoveFromNode(RemovedRecord, *NextRemoveFromNode, Mode);
  }

  // Case 3b
  assert(LeftNumKeys == Degree - 1 || RightNumKeys == Degree - 1);

  // Right node is always merged into left node. This figures out which
  // ones to use depending on what's available.
  auto MergeLeftNode = RightSibling ? NextRemoveFromNode : LeftSibling;
  auto MergeRightNode = RightSibling ? RightSibling : NextRemoveFromNode;
  unsigned PushedDownKeyIndex = RightSibling ? I : I - 1;
  RecordPointer PushedDownKey = InternalNode.getKey(PushedDownKeyIndex);
  deleteKeyAtIndex(InternalNode, PushedDownKeyIndex);

  // Append all sibling node onto node
  mergeNodes(*MergeLeftNode, *MergeRightNode, PushedDownKey);
  // Delete right node we just copied into left
  Storage.freeRecord(MergeRightNode->NodeRec);
  RecordPointer Removed = tryRemoveFromNode(RemovedRecord, *MergeLeftNode,
      Mode);

  Node RootNodeObj (*this, RootNode);
  if (RootNodeObj.getNumKeys() == 0) {
    makeRoot(RootNodeObj.getChild(0));
  }
  return Removed;
}

void BTree::mergeNodes(Node &LeftDestinationNode, Node &RightSourceNode,
    RecordPointer GlueKey) {
  unsigned WritePos = LeftDestinationNode.getNumKeys();
  LeftDestinationNode.putKey(WritePos, GlueKey);
  LeftDestinationNode.putChild(++WritePos, RightSourceNode.getChild(0));
  for (unsigned ReadPos = 0; ReadPos < RightSourceNode.getNumKeys();
      ++WritePos, ++ReadPos) {
    LeftDestinationNode.putKey(WritePos, RightSourceNode.getKey(ReadPos));
    LeftDestinationNode.putChild(WritePos + 1,
        RightSourceNode.getChild(ReadPos + 1));
  }
}

void BTree::insertKeyAtIndex(Node &RemovedFrom, unsigned InsertIndex,
    RecordPointer Key) {
  assert(
      InsertIndex <= MaxNumKeys - 1 && RemovedFrom.getNumKeys() < MaxNumKeys);
  // Offset everything by one starting at the end until we reach the insert
  // index
  for (unsigned ReadIndex = RemovedFrom.getNumKeys(); ReadIndex >= 1;
      --ReadIndex) {
    RemovedFrom.putKey(ReadIndex, RemovedFrom.getKey(ReadIndex - 1));
    RemovedFrom.putChild(ReadIndex + 1, RemovedFrom.getChild(ReadIndex));
  }
  RemovedFrom.putKey(0, Key);
  RemovedFrom.putChild(1, RemovedFrom.getChild(0));
  //Note: this leaves child 0 up to the caller to set
}

void BTree::deleteKeyAtIndex(Node &RemovedFrom, unsigned Index) {
  // Offset everything by one starting at Index
  for (unsigned ReadIndex = Index; ReadIndex < RemovedFrom.getNumKeys() - 1;
      ++ReadIndex) {
    RemovedFrom.putKey(ReadIndex, RemovedFrom.getKey(ReadIndex + 1));
    RemovedFrom.putChild(ReadIndex + 1, RemovedFrom.getChild(ReadIndex + 2));
  }
  // Remove last entry, otherwise it will be duplicated
  unsigned Last = RemovedFrom.getNumKeys() - 1;
  RemovedFrom.putKey(Last, INVALID_KEY);
  RemovedFrom.putChild(Last + 1, INVALID_CHILDREN);
}

void BTree::accept(BTreeVisitor& Visitor) {
  search(RootNode, Visitor);
}

void BTree::search(RecordPointer SearchedNodeRec, BTreeVisitor& Visitor) {
  if (SearchedNodeRec == 0) {
    return;
  }

  Node SearchedNode (*this, SearchedNodeRec);
  unsigned I = 0;
  for (; I < MaxNumKeys; I++) {
    RecordPointer Key = SearchedNode.getKey(I);
    if (Key == INVALID_KEY) {
      break;
    }
    int Compare = Visitor.compare(Key);
    if (Compare == 0) {
      // Allow visitor to find multiple matches
      search(SearchedNode.getChild(I), Visitor);

      Visitor.visit(Key);
    } else if (Compare > 0) {
      break;
    }
  }
  if (!SearchedNode.isLeaf()) {
    search(SearchedNode.getChild(I), Visitor);
  }
}

void BTree::dump(std::function<void(RecordPointer, llvm::raw_ostream &OS)> Func,
    llvm::raw_ostream &OS) {
  if (RootNode == 0) {
    return;
  }

  Node RootNodeObj(*this, RootNode);
  dump(Func, OS, RootNodeObj, 0);
}

void BTree::dump(std::function<void(RecordPointer, llvm::raw_ostream &OS)> Func,
    llvm::raw_ostream &OS, Node &NodeObj, unsigned Depth) {
  const unsigned INDENT_SPACES_PER_DEPTH = 4;

  unsigned NumKeys = NodeObj.getNumKeys();
  if (NumKeys == 0) {
    OS << "Nothing\n";
    return;
  }
  for (unsigned I = NumKeys - 1;; --I) {
    RecordPointer Child = NodeObj.getChild(I + 1);
    if (Child != INVALID_CHILDREN) {
      Node ChildNode(*this, Child);
      dump(Func, OS, ChildNode, Depth + 1);
    } else {
      OS.indent(Depth * INDENT_SPACES_PER_DEPTH);
      OS << "  |\n";
    }
    OS.indent(Depth * INDENT_SPACES_PER_DEPTH);
    Func(NodeObj.getKey(I), OS);
    OS << "\n";

    if (I == 0) {
      RecordPointer Child = NodeObj.getChild(I);
      if (Child != INVALID_CHILDREN) {
        Node ChildNode(*this, Child);
        dump(Func, OS, ChildNode, Depth + 1);
      } else {
        OS.indent(Depth * INDENT_SPACES_PER_DEPTH);
        OS << "  |\n";
      }
      break;
    }
  }
}

BTree::Node::Node(BTree &Tree, RecordPointer NodeRec) :
    Tree(Tree), NodeRec(NodeRec) {
  Piece = Tree.Storage.getDataPiece(NodeRec);
}

RecordPointer BTree::Node::getChild(unsigned Idx) {
  return Piece->getRecPtr(
      NodeRec + Tree.ChildrenOffset + Idx * ClangdIndexDataStorage::PTR_SIZE);
}

void BTree::Node::putChild(unsigned Idx, RecordPointer Rec) {
  Piece->putRecPtr(
      NodeRec + Tree.ChildrenOffset + Idx * ClangdIndexDataStorage::PTR_SIZE,
      Rec);
}

void BTree::Node::putKey(unsigned Idx, RecordPointer Rec) {
  Piece->putRecPtr(NodeRec + Idx * ClangdIndexDataStorage::PTR_SIZE, Rec);
}

unsigned BTree::Node::getNumKeys() {
  unsigned NumKeys = 0;
  for (unsigned J = 0; J < Tree.MaxNumKeys; J++) {
    RecordPointer Key = getKey(J);
    if (Key == INVALID_KEY) {
      break;
    }
    NumKeys++;
  }
  return NumKeys;
}

unsigned BTree::Node::getNumChildren() {
  unsigned NumChilden = 0;
  for (; NumChilden <= Tree.MaxNumKeys; NumChilden++) {
    if (getChild(NumChilden) == INVALID_CHILDREN)
      break;
  }
  return NumChilden;
}

RecordPointer BTree::Node::getKey(unsigned Idx) {
  return Piece->getRecPtr(NodeRec + Idx * ClangdIndexDataStorage::PTR_SIZE);
}

bool BTree::Node::isFull() {
  return getKey(Tree.MaxNumKeys - 1) != INVALID_KEY;
}

bool BTree::Node::isLeaf() {
  return getChild(0) == INVALID_CHILDREN;
}

} /* namespace clangd */
} /* namespace clang */
