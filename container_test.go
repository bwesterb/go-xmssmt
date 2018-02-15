package xmssmt

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestFSContainerCache(t *testing.T) {
	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctr, err := OpenFSPrivateKeyContainer(dir + "/key")
	if err != nil {
		t.Fatalf("OpenFSPrivateKeyContainer: %v", err)
	}

	if ctr.Initialized() != nil {
		t.Fatalf("Container should not be initialized at this point")
	}

	params := ParamsFromName("XMSSMT-SHA2_60/12_256")
	if params == nil {
		t.Fatalf("ParamsFromName() failed")
	}
	sk := make([]byte, params.PrivateKeySize())
	for i := 0; i < len(sk); i++ {
		sk[i] = byte(i)
	}
	err = ctr.Reset(sk, *params)
	if err != nil {
		t.Fatalf("Reset(): %v", err)
	}

	addr1 := SubTreeAddress{0, 1}
	addr2 := SubTreeAddress{0, 2}
	addr3 := SubTreeAddress{1, 0}
	addr4 := SubTreeAddress{1, 1}

	buf1, exists1, err := ctr.GetSubTree(addr1)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	buf2, exists2, err := ctr.GetSubTree(addr2)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}

	if exists1 || exists2 {
		t.Fatalf("These trees should not exist")
	}

	for i := 0; i < params.SubTreeSize(); i++ {
		buf1[i] = byte(i * 2)
		buf2[i] = byte(i * 3)
	}

	buf1b, exists1, err := ctr.GetSubTree(addr1)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	if !exists1 {
		t.Fatalf("This tree should exist")
	}
	if &buf1b[0] != &buf1[0] {
		t.Fatalf("This should be the same subtree")
	}

	err = ctr.DropSubTree(addr1)
	if err != nil {
		t.Fatalf("DropSubTree: %v", err)
	}

	_, exists3, err := ctr.GetSubTree(addr3)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	if exists3 {
		t.Fatalf("This tree should not exist")
	}

	buf1, exists1, err = ctr.GetSubTree(addr1)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	if exists1 {
		t.Fatalf("This tree should not exist")
	}

	err = ctr.DropSubTree(addr3)
	if err != nil {
		t.Fatalf("DropSubTree: %v", err)
	}

	for i := 0; i < params.SubTreeSize(); i++ {
		buf1[i] = byte(i * 2)
	}

	if err = ctr.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	ctr, err = OpenFSPrivateKeyContainer(dir + "/key")
	if err != nil {
		t.Fatalf("OpenFSPrivateKeyContainer: %v", err)
	}

	if ctr.Initialized() == nil {
		t.Fatalf("This container should be initialized")
	}
	if !reflect.DeepEqual(ctr.Initialized(), params) {
		t.Fatalf("Container did not store parameters correctly")
	}
	if !ctr.CacheInitialized() {
		t.Fatalf("This cache should be initialized")
	}

	subTrees, err := ctr.ListSubTrees()
	if err != nil {
		t.Fatalf("ListSubTrees: %v", err)
	}
	if len(subTrees) != 2 {
		t.Fatalf("Should have 2 subtrees")
	}

	buf1, exists1, err = ctr.GetSubTree(addr1)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	buf2, exists2, err = ctr.GetSubTree(addr2)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	if !exists1 || !exists2 {
		t.Fatalf("These trees should exist")
	}

	ok := true
	for i := 0; i < params.SubTreeSize(); i++ {
		if buf1[i] != byte(i*2) || buf2[i] != byte(i*3) {
			ok = false
		}
	}
	if !ok {
		t.Fatalf("The trees did not retain their correct values")
	}

	_, exists3, err = ctr.GetSubTree(addr3)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	_, exists4, err := ctr.GetSubTree(addr4)
	if err != nil {
		t.Fatalf("GetSubTree: %v", err)
	}
	if exists3 || exists4 {
		t.Fatalf("These trees should not exist")
	}
	if err = ctr.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}
