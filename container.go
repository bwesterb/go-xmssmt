package xmssmt

import (
	"container/heap"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bwesterb/byteswriter"
	"github.com/hashicorp/go-multierror"
	"github.com/nightlyone/lockfile"
)

// A PrivateKeyContainer has two tasks
//
//  1. It has to store the XMSS[MT] secret key and sequence number of the first
//     unused signature.
//  2. It has to cache the precomputed subtrees to increase signing performance.
//
// NOTE A PrivateKeyContainer does not have to be thread safe.
type PrivateKeyContainer interface {
	// Reset (or initialize) the cache that stores the subtrees.  It is always
	// called before use.
	ResetCache() Error

	// Returns the buffer for the given subtree.  If the subtree does not
	// have a buffer yet, allocate it of the size params.CachedSubTreeSize()
	// with params as specified in the last call to Reset().
	// The exists return value indicates whether the subtree was present.
	// The container should write changes to buf back to the storage.
	// The containe does not have to ensure integrity, a checksum is added
	// to the end of the buffer.
	GetSubTree(address SubTreeAddress) (buf []byte, exists bool, err Error)

	// Returns whether the given subtree is in the cache.  Returns false
	// if the cache is not initialized.
	HasSubTree(address SubTreeAddress) bool

	// Drops the given subtree from the cache (if it was even cached to begin
	// with).
	DropSubTree(address SubTreeAddress) Error

	// Returns the list of cached subtrees
	ListSubTrees() ([]SubTreeAddress, Error)

	// Reset (or initialize) the container with the given private key
	// and parameters.  Calls ResetCache().
	Reset(privateKey []byte, params Params) Error

	// Returns the current signature sequence number and increment
	// the stored sequence number by the given amount.
	// The user can use the signatures in this range freely,
	// but should call SetSeqNo() later to record the actual number
	// of signatures used.
	BorrowSeqNos(amount uint32) (SignatureSeqNo, Error)

	// Sets the signature sequence number to the given value.
	// Removes the possible-lost-signatures record set by BorrowSeqNos.
	SetSeqNo(seqNo SignatureSeqNo) Error

	// Returns the current signature sequence number.
	// If BorrowSeqNos() has been called without corresponding SetSeqNo()
	// there might have been signatures lost.  In that case, calls to
	// GetSeqNo will return the number of possibly lost signatures
	// until SetSeqNo() has been called.
	GetSeqNo() (seqNo SignatureSeqNo, lostSigs uint32, err Error)

	// Returns the private key.
	GetPrivateKey() ([]byte, Error)

	// Returns the algorithm parameters if the container is initialized
	// (eg. the file exist) and nil if not.
	Initialized() *Params

	// Returns whether the cache is initialized.  If not,  it can be
	// initialized by calling ResetCache().
	CacheInitialized() bool

	// Closes the container.
	Close() Error
}

// PrivateKeyContainer backed by three files:
//
//   path/to/key        contains the secret key and signature sequence number
//   path/to/key.lock   a lockfile
//   path/to/key.cache  cached subtrees
type fsContainer struct {
	// Fields relevant to a container, initialized or not
	flock            lockfile.Lockfile // file lock
	path             string            // absolute base path
	initialized      bool
	cacheInitialized bool
	closed           bool

	// Fields set in an initialized container
	params     Params // parameters of the algorithm
	privateKey []byte
	seqNo      SignatureSeqNo
	borrowed   uint32

	// Fields relevant to a container with an initialized cache
	cacheFile         *os.File // the opened cache file
	allocatedSubTrees uint32   // number of allocated cached subtrees
	// maps subtree address to the index of the subtree in the cache
	cacheIdxLut map[SubTreeAddress]uint32
	// maps subtree address to an mmaped buffer
	cacheBufLut  map[SubTreeAddress][]byte
	cacheFreeIdx *uint32Heap // list of allocated but unused subtrees

}

const (
	// First 8 bytes (in hex) of the secret key file
	FS_CONTAINER_KEY_MAGIC = "4089430a5ced6844"

	// First 8 bytes (in hex) of the subtree cache file
	FS_CONTAINER_CACHE_MAGIC = "e77957607ef79446"
)

// Returns a PrivateKeyContainer backed by the filesystem.
func OpenFSPrivateKeyContainer(path string) (PrivateKeyContainer, Error) {
	var ctr fsContainer
	var err error

	ctr.path, err = filepath.Abs(path)
	if err != nil {
		return nil, wrapErrorf(err,
			"Could not turn %s into an absolute path", path)
	}

	// Acquire lock
	lockFilePath := ctr.path + ".lock"
	ctr.flock, err = lockfile.New(lockFilePath)
	if err != nil {
		return nil, wrapErrorf(err,
			"Failed to create lockfile %s", lockFilePath)
	}

	err = ctr.flock.TryLock()
	if _, ok := err.(interface {
		Temporary() bool
	}); ok {
		err2 := errorf("%s is locked", path)
		err2.locked = true
		return nil, err2
	}

	// Check if the container exists
	if _, err = os.Stat(ctr.path); os.IsNotExist(err) {
		return &ctr, nil
	}

	// Open the container.
	file, err := os.Open(ctr.path)
	if err != nil {
		return &ctr, wrapErrorf(err, "Failed to open keyfile %s", path)
	}
	defer file.Close()

	var keyHeader fsKeyHeader
	err = binary.Read(file, binary.BigEndian, &keyHeader)
	if err != nil {
		return &ctr, wrapErrorf(err, "Failed to read keyfile header")
	}

	if FS_CONTAINER_KEY_MAGIC != hex.EncodeToString(keyHeader.Magic[:]) {
		return &ctr, wrapErrorf(err, "Keyfile has invalid magic")
	}

	ctr.params = keyHeader.Params
	ctr.privateKey = make([]byte, ctr.params.PrivateKeySize())
	ctr.seqNo = keyHeader.SeqNo
	ctr.borrowed = keyHeader.Borrowed
	_, err = io.ReadAtLeast(file, ctr.privateKey, ctr.params.PrivateKeySize())
	if err != nil {
		return &ctr, wrapErrorf(err, "Failed to read private key")
	}

	ctr.initialized = true

	return &ctr, ctr.openCache()
}

func (ctr *fsContainer) openCache() Error {
	var err error

	ctr.cacheIdxLut = make(map[SubTreeAddress]uint32)
	ctr.cacheBufLut = make(map[SubTreeAddress][]byte)
	emptyHeap := uint32Heap([]uint32{})
	ctr.cacheFreeIdx = &emptyHeap
	heap.Init(ctr.cacheFreeIdx)

	// Open cache file
	cachePath := ctr.path + ".cache"
	ctr.cacheFile, err = os.OpenFile(cachePath, os.O_RDWR, 0)
	if err != nil {
		return wrapErrorf(err, "Failed to open cache file")
	}

	// Read header
	var header fsCacheHeader
	err = binary.Read(ctr.cacheFile, binary.BigEndian, &header)
	if err != nil {
		return wrapErrorf(err, "Failed to read cache file header")
	}

	if FS_CONTAINER_CACHE_MAGIC != hex.EncodeToString(header.Magic[:]) {
		return wrapErrorf(err, "Cache file magic is wrong")
	}

	ctr.allocatedSubTrees = header.AllocatedSubTrees

	// Read subtrees
	var idx uint32
	for idx = 0; idx < ctr.allocatedSubTrees; idx++ {
		_, err = ctr.cacheFile.Seek(int64(ctr.subTreeOffset(idx)), 0)
		if err != nil {
			return wrapErrorf(err, "Failed to seek to subtree in cache")
		}

		var treeHeader fsSubTreeHeader
		err = binary.Read(ctr.cacheFile, binary.BigEndian, &treeHeader)
		if err != nil {
			return wrapErrorf(err, "Failed to read subtree header in cache")
		}

		if treeHeader.Allocated == 0 {
			heap.Push(ctr.cacheFreeIdx, idx)
		} else {
			ctr.cacheIdxLut[treeHeader.Address] = idx
		}
	}

	ctr.cacheInitialized = true

	return nil
}

// Header of the key file
type fsKeyHeader struct {
	Magic    [8]byte        // Should be FS_CONTAINER_KEY_MAGIC
	Params   Params         // Parameters
	SeqNo    SignatureSeqNo // Signature seqno
	Borrowed uint32         // Number of signatures borrowed.
}

// Header of the cache file
type fsCacheHeader struct {
	Magic             [8]byte // Should be FS_CONTAINER_CACHE_MAGIC
	AllocatedSubTrees uint32  // Number of allocated subtrees
}

// Header of a cached subtree
type fsSubTreeHeader struct {
	// In older versions of Go, binary.Read/Write do not support bool
	Allocated uint8
	Address   SubTreeAddress
}

func (ctr *fsContainer) CacheInitialized() bool {
	return ctr.cacheInitialized
}

func (ctr *fsContainer) Initialized() *Params {
	if !ctr.initialized {
		return nil
	}
	return &ctr.params
}

func (ctr *fsContainer) ResetCache() Error {
	var err Error
	var err2 error

	if !ctr.initialized {
		err = errorf("Container is not initialized")
		return err
	}

	// Close old cache
	if ctr.cacheInitialized {
		ctr.closeCache() // we ignore munmap failures
	}
	ctr.cacheBufLut = make(map[SubTreeAddress][]byte)
	ctr.cacheIdxLut = make(map[SubTreeAddress]uint32)
	ctr.allocatedSubTrees = 0
	emptyHeap := uint32Heap([]uint32{})
	ctr.cacheFreeIdx = &emptyHeap
	heap.Init(ctr.cacheFreeIdx)

	// Open new cache
	cachePath := ctr.path + ".cache"
	ctr.cacheFile, err2 = os.OpenFile(
		cachePath,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC,
		0600)
	if err2 != nil {
		return wrapErrorf(err, "failed to create cache file")
	}

	if err = ctr.writeCacheHeader(); err != nil {
		return err
	}
	ctr.cacheInitialized = true

	return nil
}

func (ctr *fsContainer) writeCacheHeader() Error {
	var err error
	_, err = ctr.cacheFile.Seek(0, 0)
	if err != nil {
		return wrapErrorf(err, "failed to seek to start of cache file")
	}
	cacheHeader := fsCacheHeader{
		AllocatedSubTrees: ctr.allocatedSubTrees,
	}
	magic, _ := hex.DecodeString(FS_CONTAINER_CACHE_MAGIC)
	copy(cacheHeader.Magic[:], magic)
	err = binary.Write(ctr.cacheFile, binary.BigEndian, &cacheHeader)
	if err != nil {
		ctr.cacheFile.Close()
		return wrapErrorf(err, "failed to write to cache file")
	}
	return nil
}

// Returns the offset of the given cached subtree entry in the cache file.
// This offset point to the 13-byte header just in front of the actual data.
func (ctr *fsContainer) subTreeOffset(idx uint32) int {
	// Find the smallest multiple of 4096 above CachedSubTreeSize() + 13,
	// where 13 is the size of fsSubTreeHeader
	paddedSize := (((ctr.params.CachedSubTreeSize() + 13) - 1) & 0xffffff000) + 4096
	return int(idx)*paddedSize + 4096
}

func (ctr *fsContainer) mmapSubTree(idx uint32) ([]byte, error) {
	buf, err := syscall.Mmap(
		int(ctr.cacheFile.Fd()),
		int64(ctr.subTreeOffset(idx)),
		ctr.params.CachedSubTreeSize()+13,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED)
	return buf, err
}

func (ctr *fsContainer) GetSubTree(address SubTreeAddress) (
	buf []byte, exists bool, err Error) {
	if !ctr.cacheInitialized {
		err = errorf("Cache is not initialized")
		return nil, false, err
	}

	var err2 error

	if buf, ok := ctr.cacheBufLut[address]; ok {
		return buf[13:], true, nil
	}

	// Check if the subtree exists
	if idx, ok := ctr.cacheIdxLut[address]; ok {
		buf, err2 = ctr.mmapSubTree(idx)
		if err2 != nil {
			return nil, false, wrapErrorf(err2, "Failed to mmap subtree")
		}
		ctr.cacheBufLut[address] = buf
		return buf[13:], true, nil
	}

	// Find a free cached subtree index
	var idx uint32
	if ctr.cacheFreeIdx.Len() != 0 {
		idx = heap.Pop(ctr.cacheFreeIdx).(uint32)
	} else {
		idx = ctr.allocatedSubTrees
		ctr.allocatedSubTrees += 1
		err2 = ctr.cacheFile.Truncate(int64(
			ctr.subTreeOffset(ctr.allocatedSubTrees)))
		if err2 != nil {
			return nil, false, wrapErrorf(err2,
				"Failed to allocate space for subtree")
		}
		err = ctr.writeCacheHeader()
		if err != nil {
			return nil, false, err
		}
	}

	buf, err2 = ctr.mmapSubTree(idx)
	if err2 != nil {
		return nil, false, wrapErrorf(err2, "Failed to mmap subtree from cache")
	}

	// Write information
	header := fsSubTreeHeader{
		Allocated: 1,
		Address:   address,
	}
	bufWriter := byteswriter.NewWriter(buf)
	err2 = binary.Write(bufWriter, binary.BigEndian, &header)
	if err2 != nil {
		err = wrapErrorf(err2, "Failed to write subtree header in cache")
		return
	}

	ctr.cacheBufLut[address] = buf
	ctr.cacheIdxLut[address] = idx

	return buf[13:], false, nil
}

func (ctr *fsContainer) ListSubTrees() ([]SubTreeAddress, Error) {
	if !ctr.cacheInitialized {
		return nil, errorf("Cache is not initialized")
	}

	ret := make([]SubTreeAddress, len(ctr.cacheIdxLut))
	i := 0
	for addr, _ := range ctr.cacheIdxLut {
		ret[i] = addr
		i++
	}
	return ret, nil
}

func (ctr *fsContainer) HasSubTree(address SubTreeAddress) bool {
	if !ctr.cacheInitialized {
		return false
	}

	_, ok := ctr.cacheIdxLut[address]
	return ok
}

func (ctr *fsContainer) DropSubTree(address SubTreeAddress) Error {
	if !ctr.cacheInitialized {
		return errorf("Cache is not initialized")
	}

	// TODO decrement allocatedSubTrees and cacheFile.Truncate when
	//      applicable to free disk space.

	var err2 error

	idx, ok := ctr.cacheIdxLut[address]
	if !ok {
		return nil
	}

	buf, ok := ctr.cacheBufLut[address]
	if !ok {
		buf, err2 = ctr.mmapSubTree(idx)
	}
	if err2 != nil {
		return wrapErrorf(err2, "Failed to mmap subtree from cache")
	}

	bufWriter := byteswriter.NewWriter(buf)
	var bFalse uint8 = 0
	err2 = binary.Write(bufWriter, binary.BigEndian, &bFalse)
	if err2 != nil {
		return wrapErrorf(err2, "Failed to write subtree header in cache")
	}

	heap.Push(ctr.cacheFreeIdx, idx)
	delete(ctr.cacheIdxLut, address)
	delete(ctr.cacheBufLut, address)

	err2 = syscall.Munmap(buf)
	if err2 != nil {
		return wrapErrorf(err2, "Failed to unmap sub tree")
	}
	return nil
}

func (ctr *fsContainer) Reset(privateKey []byte, params Params) Error {
	if ctr.closed {
		return errorf("Container is closed")
	}

	// Even if closing the cache fails, we will try to write the key file.
	closeCacheErr := ctr.closeCache()

	ctr.params = params
	ctr.privateKey = privateKey
	ctr.seqNo = 0
	ctr.borrowed = 0
	ctr.cacheInitialized = false

	if err := ctr.writeKeyFile(); err != nil {
		return err
	}

	if closeCacheErr != nil {
		return wrapErrorf(closeCacheErr, "Failed to close old cache")
	}

	ctr.initialized = true

	if err := ctr.ResetCache(); err != nil {
		return err
	}

	return nil
}

func (ctr *fsContainer) BorrowSeqNos(amount uint32) (SignatureSeqNo, Error) {
	if !ctr.initialized {
		return 0, errorf("Container is not initialized")
	}

	ctr.borrowed += amount
	ctr.seqNo += SignatureSeqNo(amount)

	if err := ctr.writeKeyFile(); err != nil {
		// rollback
		ctr.borrowed -= amount
		ctr.seqNo -= SignatureSeqNo(amount)
		return 0, err
	}

	return ctr.seqNo - SignatureSeqNo(amount), nil
}

// Write key file to disk
func (ctr *fsContainer) writeKeyFile() Error {
	var err error

	// (1) Write to a temp file.  (2) fsync this tempfile to get the data out.
	// (3) Rename the tempfile to the acutal key file.  (4) Finally, fsync
	// the parent directory.
	tmpPath := ctr.path + ".tmp"
	tmpFile, err := os.OpenFile(
		tmpPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600)
	if err != nil {
		return wrapErrorf(err, "failed to create temporary key file")
	}

	// (1) Write temp file.
	keyHeader := fsKeyHeader{
		Params:   ctr.params,
		SeqNo:    ctr.seqNo,
		Borrowed: ctr.borrowed,
	}
	magic, _ := hex.DecodeString(FS_CONTAINER_KEY_MAGIC)
	copy(keyHeader.Magic[:], magic)
	if err = binary.Write(tmpFile, binary.BigEndian, &keyHeader); err != nil {
		tmpFile.Close()
		return wrapErrorf(err, "failed to write temporary key file")
	}

	if _, err = tmpFile.Write(ctr.privateKey); err != nil {
		tmpFile.Close()
		return wrapErrorf(err, "failed to write temporary key file")
	}

	// (2) Sync the tempfile
	if err = tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return wrapErrorf(err, "failed to sync temporary key file")
	}

	if err = tmpFile.Close(); err != nil {
		return wrapErrorf(err, "failed to close temporary key file")
	}

	// (3) Rename the tempfile
	if err = os.Rename(tmpPath, ctr.path); err != nil {
		return wrapErrorf(err, "failed to replace key file")
	}

	// (4) Sync the parent directory.  If this fails we have no way of knowing
	// whether  the changes have been written out to disk.  We will assume that
	// it did not, so that we won't reuse signatures.
	dirName := filepath.Dir(ctr.path)
	dirFd, err := syscall.Open(
		filepath.Dir(ctr.path),
		syscall.O_DIRECTORY,
		syscall.O_RDWR)
	if err != nil {
		return wrapErrorf(err, "failed to sync key file: open(%s):", dirName)
	}

	if err = syscall.Fsync(dirFd); err != nil {
		syscall.Close(dirFd)
		return wrapErrorf(err, "failed to sync key file")
	}

	if err = syscall.Close(dirFd); err != nil {
		return wrapErrorf(err, "failed to sync key file (close)")
	}

	return nil
}

func (ctr *fsContainer) SetSeqNo(seqNo SignatureSeqNo) Error {
	if !ctr.initialized {
		return errorf("Container is not initialized")
	}

	oldBorrowed := ctr.borrowed
	oldSeqNo := ctr.seqNo
	ctr.borrowed = 0
	ctr.seqNo = seqNo

	if err := ctr.writeKeyFile(); err != nil {
		// rollback
		ctr.borrowed = oldBorrowed
		ctr.seqNo = oldSeqNo
		return err
	}

	return nil
}

func (ctr *fsContainer) GetSeqNo() (
	seqNo SignatureSeqNo, lostSigs uint32, err Error) {
	if !ctr.initialized {
		err = errorf("Container is not initialized")
		return
	}

	return ctr.seqNo, ctr.borrowed, nil
}

func (ctr *fsContainer) GetPrivateKey() ([]byte, Error) {
	if !ctr.initialized {
		return nil, errorf("Container is not initialized")
	}
	return ctr.privateKey, nil
}

func (ctr *fsContainer) closeCache() (err error) {
	ctr.cacheInitialized = false
	if ctr.cacheBufLut != nil {
		for _, buf := range ctr.cacheBufLut {
			if err2 := syscall.Munmap(buf); err2 != nil {
				err = multierror.Append(err, wrapErrorf(err2,
					"Failed to unmap cached subtree"))
			}
		}
		ctr.cacheBufLut = nil
	}
	if ctr.cacheFile != nil {
		if err2 := ctr.cacheFile.Close(); err2 != nil {
			err = multierror.Append(err, wrapErrorf(err2,
				"Failed to close cache file"))
		}
		ctr.cacheFile = nil
	}
	return
}

func (ctr *fsContainer) Close() Error {
	var err error
	if err2 := ctr.closeCache(); err2 != nil {
		err = multierror.Append(err, wrapErrorf(err2,
			"Could not close cache"))
	}
	if err2 := ctr.flock.Unlock(); err2 != nil {
		err = multierror.Append(err, wrapErrorf(err2,
			"Could not release file lock"))
	}
	ctr.closed = true
	ctr.initialized = false

	if err != nil {
		return wrapErrorf(err, "")
	}
	return nil
}
