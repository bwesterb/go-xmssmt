package xmssmt

import (
	"encoding/binary"
)

const (
	ADDR_TYPE_OTS      = 0
	ADDR_TYPE_LTREE    = 1
	ADDR_TYPE_HASHTREE = 2
)

// Address used in XMSS[MT] to diversify the hashes.  See eg prfAddrInto().
type address [8]uint32

// Represents the position of a subtree in the full XMSSMT tree.
type SubTreeAddress struct {
	// The height of the subtree.  The leaf-subtrees have layer=0
	Layer uint32

	// The offset in the subtree.  The leftmost subtrees have tree=0
	Tree uint64
}

// Converts to address
func (sta *SubTreeAddress) address() (addr address) {
	addr.setLayer(sta.Layer)
	addr.setTree(sta.Tree)
	return
}

func (addr *address) setLayer(layer uint32) {
	addr[0] = layer
}

func (addr *address) setTree(tree uint64) {
	addr[1] = uint32(tree >> 32)
	addr[2] = uint32(tree)
}

func (addr *address) setType(typ uint32) {
	addr[3] = typ
}

func (addr *address) setKeyAndMask(keyAndMask uint32) {
	addr[7] = keyAndMask
}

func (addr *address) setSubTreeFrom(other address) {
	addr[0] = other[0]
	addr[1] = other[1]
	addr[2] = other[2]
}

func (addr *address) setOTS(ots uint32) {
	addr[4] = ots
}

func (addr *address) setChain(chain uint32) {
	addr[5] = chain
}

func (addr *address) setHash(hash uint32) {
	addr[6] = hash
}

func (addr *address) setLTree(ltree uint32) {
	addr[4] = ltree
}

func (addr *address) setTreeHeight(treeHeight uint32) {
	addr[5] = treeHeight
}

func (addr *address) setTreeIndex(treeIndex uint32) {
	addr[6] = treeIndex
}

func (addr *address) writeInto(buf []byte) {
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], addr[i])
	}
}
