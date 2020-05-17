//go:generate go run f1600x4_amd64_src.go -out f1600x4_amd64.s -stubs f1600x4_amd64_stubs.go

package f1600x4

import (
	"golang.org/x/sys/cpu"

	"unsafe"
)

// Available is true when this system supports a fast fourway KeccaK-f[1600].
var Available = cpu.X86.HasAVX2

// Contains state for the fourway permutation including the four
// interleaved [25]uint64 buffers.  Call Initialize() before use to initialize
// and get a pointer to the interleaved buffer.
type State struct {
	// Go guarantees a to be aligned on 8 bytes, whereas we need it to be
	// aligned on 32 bytes for bet performance.  Thus we leave some headroom
	// to be able to move the start of the state.

	// 4 x 25 uint64s for the interleaved states and three uint64s headroom
	// to fix allignment.
	a [103]uint64

	// Offset into a that is 32 byte aligned.
	offset int
}

// Initialize the state and returns the buffer on which the four permutations
// will act: a uint64 slice of length 100.  The first permutation will act
// on {a[0], a[4], ..., a[96]}, the second on {a[1], a[5], ..., a[97]}, etc.
func (s *State) Initialize() []uint64 {
	rp := unsafe.Pointer(&s.a[0])

	// remainder of address modulo 32
	rem := (int(uintptr(rp)&31) >> 3)

	if rem != 0 {
		s.offset = 4 - rem
	}

	// the slice we return will be aligned on 32 byte boundary.
	return s.a[s.offset : s.offset+100]
}

// Zeroes internal buffer.
func (s *State) Zero() {
	s.a = [103]uint64{}
}

// Perform the four parallel KeccaK-f[1600]s interleaved on the slice returned
// from Initialize().
func (s *State) Permute() {
	f1600x4(&s.a[s.offset], &rc)
}

// Round constants
var rc = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}
