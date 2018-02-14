package xmssmt

import (
	"path/filepath"

	"github.com/nightlyone/lockfile"
)

// A PrivateKeyContainer has two tasks
//
//  1. It has to store the XMSS[MT] secret key and sequence number of the first
//     unused signature.
//  2. It has to cache the precomputed subtrees to increase signing performance.
type PrivateKeyContainer interface {
	// Reset (or initialize) the cache that stores the subtrees.  It is always
	// called before use.
	// subTreeSize is the size that the buffers returned by
	// AllocateSubTree should have.
	ResetCache(subTreeSize int) Error

	// Returns the buffer for the given subtree.  If the subtree does not
	// have a buffer yet, allocate it of the size specified in ResetCache().
	// The exists return value indicates whether the subtree was present.
	GetSubTree(address SubTreeAddress) (buf []byte, exists bool, err Error)

	// Drops the given subtree from the cache.
	DropSubTree(address SubTreeAddress) Error

	// Reset (or initialize) the container with the given secret key.
	// Calls ResetCache(subTreeSize).
	Reset(secretKey []byte, subTreeSize int) Error

	// Returns the current signature sequence number and increment
	// the stored sequence number by the given amount.
	// The user can use the signatures in this range freely,
	// but should call SetSeqNo() later to record the actual number
	// of signatures used.
	BorrowSeqNos(amount uint) (SignatureSeqNo, Error)

	// Sets the signature sequence number to the given value.
	// Removes the possible-lost-signatures record set by BorrowSeqNos.
	SetSeqNo(seqNo SignatureSeqNo) Error

	// Returns the current signature sequence number.
	// If BorrowSeqNos() has been called without corresponding SetSeqNo()
	// there might have been signatures lost.  In that case, calls to
	// GetSeqNo will return the number of possibly lost signatures
	// until SetSeqNo() has been called.
	GetSeqNo() (seqNo SignatureSeqNo, lostSigs uint, err Error)

	// Returns whether the container is initialized (eg. whether its
	// files exist.)
	Initialized() bool
}

// Represents the position of a subtree in the full XMSSMT tree.
type SubTreeAddress struct {
	// The height of the subtree.  The leaf-subtrees have layer=0
	Layer uint32

	// The offset in the subtree.  The leftmost subtrees have tree=0
	Tree uint64
}

// PrivateKeyContainer backed by three files:
//
//   path/to/key        contains the secret key and signature sequence number
//   path/to/key.lock   a lockfile
//   path/to/key.cache  cached subtrees
type fsContainer struct {
	flock       lockfile.Lockfile // file lock
	path        string            // absolute base path
	initialized bool
}

// Returns a PrivateKeyContainer backed by the filesystem.
func OpenFSPrivateKeyContainer(path string) (PrivateKeyContainer, Error) {
	var ctr fsContainer
	var err error

	ctr.path, err = filepath.Abs(path)
	if err != nil {
		return nil, wrapErrorf(err, "Could not turn %s into an absolute path", path)
	}

	lockFilePath := ctr.path + ".lock"
	ctr.flock, err = lockfile.New(lockFilePath)
	if err != nil {
		return nil, wrapErrorf(err, "Failed to create lockfile %s", lockFilePath)
	}

	err = ctr.flock.TryLock()
	if _, ok := err.(interface {
		Temporary() bool
	}); ok {
		err2 := errorf("%s is locked", path)
		err2.locked = true
		return nil, err2
	}

	// TODO finish

	return &ctr, nil
}
