package xmssmt

type address [8]uint32

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

func (addr *address) toBytes() []byte {
	buf := make([]byte, 32)
	for i := 0; i < 8; i++ {
		copy(buf[i*4:], encodeUint64(uint64(addr[i]), 4))
	}
	return buf
}
