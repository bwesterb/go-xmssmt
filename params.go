//go:generate enumer -type HashFunc

package xmssmt

import (
	"encoding/binary"
	"fmt"
	"reflect"
)

type HashFunc uint8

const (
	SHA2 HashFunc = iota
	SHAKE
)

// Parameters of an XMSS[MT] instance
type Params struct {
	Func       HashFunc // which has function to use
	N          uint32   // security parameter: influences length of hashes
	FullHeight uint32   // full height of tree
	D          uint32   // number of subtrees; 1 for XMSS, >1 for XMSSMT

	// WOTS+ Winternitz parameter.  Only 4, 16 and 256 are supported.
	WotsW uint16
}

func (p *Params) String() string {
	wString := ""
	if p.WotsW != 16 {
		wString = fmt.Sprintf(";w=%d", p.WotsW)
	}
	if p.D == 1 {
		return fmt.Sprintf("XMSS-%s_%d_%d%s",
			p.Func, p.FullHeight, p.N*8, wString)
	}
	return fmt.Sprintf("XMSSMT-%s_%d/%d_%d%s",
		p.Func, p.FullHeight, p.D, p.N*8, wString)
}

// Registry of named XMSS[MT] algorithms
var registry []regEntry = []regEntry{
	{"XMSSMT-SHA2_20/2_256", true, 0x00000001, Params{SHA2, 32, 20, 2, 16}},
	{"XMSSMT-SHA2_20/4_256", true, 0x00000002, Params{SHA2, 32, 20, 4, 16}},
	{"XMSSMT-SHA2_40/2_256", true, 0x00000003, Params{SHA2, 32, 40, 2, 16}},
	{"XMSSMT-SHA2_40/4_256", true, 0x00000004, Params{SHA2, 32, 40, 4, 16}},
	{"XMSSMT-SHA2_40/8_256", true, 0x00000005, Params{SHA2, 32, 40, 8, 16}},
	{"XMSSMT-SHA2_60/3_256", true, 0x00000006, Params{SHA2, 32, 60, 3, 16}},
	{"XMSSMT-SHA2_60/6_256", true, 0x00000007, Params{SHA2, 32, 60, 6, 16}},
	{"XMSSMT-SHA2_60/12_256", true, 0x00000008, Params{SHA2, 32, 60, 12, 16}},

	{"XMSSMT-SHA2_20/2_512", true, 0x00000009, Params{SHA2, 64, 20, 2, 16}},
	{"XMSSMT-SHA2_20/4_512", true, 0x0000000a, Params{SHA2, 64, 20, 4, 16}},
	{"XMSSMT-SHA2_40/2_512", true, 0x0000000b, Params{SHA2, 64, 40, 2, 16}},
	{"XMSSMT-SHA2_40/4_512", true, 0x0000000c, Params{SHA2, 64, 40, 4, 16}},
	{"XMSSMT-SHA2_40/8_512", true, 0x0000000d, Params{SHA2, 64, 40, 8, 16}},
	{"XMSSMT-SHA2_60/3_512", true, 0x0000000e, Params{SHA2, 64, 60, 3, 16}},
	{"XMSSMT-SHA2_60/6_512", true, 0x0000000f, Params{SHA2, 64, 60, 6, 16}},
	{"XMSSMT-SHA2_60/12_512", true, 0x00000010, Params{SHA2, 64, 60, 12, 16}},

	{"XMSSMT-SHAKE_20/2_256", true, 0x00000011, Params{SHAKE, 32, 20, 2, 16}},
	{"XMSSMT-SHAKE_20/4_256", true, 0x00000012, Params{SHAKE, 32, 20, 4, 16}},
	{"XMSSMT-SHAKE_40/2_256", true, 0x00000013, Params{SHAKE, 32, 40, 2, 16}},
	{"XMSSMT-SHAKE_40/4_256", true, 0x00000014, Params{SHAKE, 32, 40, 4, 16}},
	{"XMSSMT-SHAKE_40/8_256", true, 0x00000015, Params{SHAKE, 32, 40, 8, 16}},
	{"XMSSMT-SHAKE_60/3_256", true, 0x00000016, Params{SHAKE, 32, 60, 3, 16}},
	{"XMSSMT-SHAKE_60/6_256", true, 0x00000017, Params{SHAKE, 32, 60, 6, 16}},
	{"XMSSMT-SHAKE_60/12_256", true, 0x00000018, Params{SHAKE, 32, 60, 12, 16}},

	{"XMSSMT-SHAKE_20/2_512", true, 0x00000019, Params{SHAKE, 64, 20, 2, 16}},
	{"XMSSMT-SHAKE_20/4_512", true, 0x0000001a, Params{SHAKE, 64, 20, 4, 16}},
	{"XMSSMT-SHAKE_40/2_512", true, 0x0000001b, Params{SHAKE, 64, 40, 2, 16}},
	{"XMSSMT-SHAKE_40/4_512", true, 0x0000001c, Params{SHAKE, 64, 40, 4, 16}},
	{"XMSSMT-SHAKE_40/8_512", true, 0x0000001d, Params{SHAKE, 64, 40, 8, 16}},
	{"XMSSMT-SHAKE_60/3_512", true, 0x0000001e, Params{SHAKE, 64, 60, 3, 16}},
	{"XMSSMT-SHAKE_60/6_512", true, 0x0000001f, Params{SHAKE, 64, 60, 6, 16}},
	{"XMSSMT-SHAKE_60/12_512", true, 0x00000020, Params{SHAKE, 64, 60, 12, 16}},

	{"XMSS-SHA2_10_256", false, 0x00000001, Params{SHA2, 32, 10, 1, 16}},
	{"XMSS-SHA2_16_256", false, 0x00000002, Params{SHA2, 32, 16, 1, 16}},
	{"XMSS-SHA2_20_256", false, 0x00000003, Params{SHA2, 32, 20, 1, 16}},
	{"XMSS-SHA2_10_512", false, 0x00000004, Params{SHA2, 64, 10, 1, 16}},
	{"XMSS-SHA2_16_512", false, 0x00000005, Params{SHA2, 64, 16, 1, 16}},
	{"XMSS-SHA2_20_512", false, 0x00000006, Params{SHA2, 64, 20, 1, 16}},

	{"XMSS-SHAKE_10_256", false, 0x00000007, Params{SHAKE, 32, 10, 1, 16}},
	{"XMSS-SHAKE_16_256", false, 0x00000008, Params{SHAKE, 32, 16, 1, 16}},
	{"XMSS-SHAKE_20_256", false, 0x00000009, Params{SHAKE, 32, 20, 1, 16}},
	{"XMSS-SHAKE_10_512", false, 0x0000000a, Params{SHAKE, 64, 10, 1, 16}},
	{"XMSS-SHAKE_16_512", false, 0x0000000b, Params{SHAKE, 64, 16, 1, 16}},
	{"XMSS-SHAKE_20_512", false, 0x0000000c, Params{SHAKE, 64, 20, 1, 16}},
}

// Encodes parameters in the reserved Oid space as follows (big endian).
//
//    8-bit magic         should be 0xEA
//    4-bit version       should be 0
//    4-bit compr-n       contains (n/8)-1 for the parameter n
//    2-bit hash          the hash function
//    2-bit w             0 for WotsW=4, 1 for WotsW=16, 2 for WotsW=256
//    6-bit full-height   the full height parameter
//    6-bit d             the parameter d
//
//  We assume XMSS if d == 1 and XMSSMT otherwise.
func (params *Params) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 4)
	err := params.WriteInto(ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Write parameters into buf as encoded by MarshalBinary().
func (params *Params) WriteInto(buf []byte) error {
	var val uint32
	var wCode uint32
	if params.N%8 != 0 {
		return errorf("N is not divisable by 8")
	}
	if params.N > 128 {
		return errorf("N is too large")
	}
	if params.Func > 1 {
		return errorf("Func is too large")
	}
	if params.FullHeight > 63 {
		return errorf("FullHeight is too large")
	}
	if params.D > 63 {
		return errorf("D is too large")
	}
	switch params.WotsW {
	case 4:
		wCode = 0
	case 16:
		wCode = 1
	case 256:
		wCode = 2
	default:
		return errorf("Only WotsW=4,16,256 are supported")
	}
	val |= 0xea << 24 // magic
	val |= ((params.N / 8) - 1) << 16
	val |= uint32(params.Func) << 14
	val |= wCode << 12
	val |= params.FullHeight << 6
	val |= params.D
	binary.BigEndian.PutUint32(buf, val)
	return nil
}

// Decodes parameters as encoded by MarshalBinary().
func (params *Params) UnmarshalBinary(buf []byte) error {
	if len(buf) != 4 {
		return errorf("Must be 4 bytes long (instead of %d)", len(buf))
	}
	val := binary.BigEndian.Uint32(buf)
	magic := val >> 24
	if magic != 0xea {
		return errorf("These are not compressed parameters (magic is wrong).")
	}
	version := (val >> 20) & ((1 << 4) - 1)
	if version != 0 {
		return errorf("Unsupported compressed parameters version")
	}
	comprN := (val >> 16) & ((1 << 4) - 1)
	wCode := (val >> 12) & ((1 << 2) - 1)
	switch wCode {
	case 0:
		params.WotsW = 4
	case 1:
		params.WotsW = 16
	case 2:
		params.WotsW = 256
	default:
		return errorf("Unsupported W-code in compressed parameters")
	}
	params.N = (comprN + 1) * 8
	params.Func = HashFunc((val >> 14) & ((1 << 2) - 1))
	params.FullHeight = (val >> 6) & ((1 << 6) - 1)
	params.D = val & ((1 << 6) - 1)
	return nil
}

// Returns the size of the subtrees for this parameter.
func (params *Params) BareSubTreeSize() int {
	height := (params.FullHeight / params.D) + 1
	return int(((1 << height) - 1) * params.N)
}

// Returns the size of the cached subtrees for this parameter.
func (params *Params) CachedSubTreeSize() int {
	// A cached subtree contains the merkle subtree,
	// space for  a WOTS+ signature of the substree above it (if it's not
	// the root) and a 64bit checksum.
	return params.BareSubTreeSize() + int(params.WotsSignatureSize()) + 8
}

// Size of the private key as stored by PrivateKeyContainer.
// NOTE this is not equal to the privateKeySize of the spec, which includes
//      the signature sequence number, OID and root
func (params *Params) PrivateKeySize() int {
	return int(params.N * 3) // skSeed + skPrf + pubSeed
}

// Entry in the registry of algorithms
type regEntry struct {
	name   string // name, eg. XMSSMT-SHA2_20/2_256
	mt     bool   // whether its XMSSMT (instead of XMSS)
	oid    uint32 // oid of the algorithm
	params Params // parameters of the algorithm
}

// Returns paramters for the named XMSS[MT] instance (and nil if there is no
// such algorithm).
func ParamsFromName(name string) *Params {
	entry, ok := registryNameLut[name]
	if ok {
		return &entry.params
	} else {
		return nil
	}
}

// List all named XMSS[MT] instances
func ListNames() (names []string) {
	names = make([]string, len(registry))
	for i, entry := range registry {
		names[i] = entry.name
	}
	return
}

// Returns the 2log of the Winternitz parameter
func (params *Params) WotsLogW() uint8 {
	switch params.WotsW {
	case 4:
		return 2
	case 16:
		return 4
	case 256:
		return 8
	default:
		panic("Only WotsW=4,16,256 are supported")
	}
}

// Returns the number of  main WOTS+ chains
func (params *Params) WotsLen1() uint32 {
	return 8 * params.N / uint32(params.WotsLogW())
}

// Returns the number of WOTS+ checksum chains
func (params *Params) WotsLen2() uint32 {
	switch params.WotsW {
	case 4:
		return 2
	case 16:
		return 3
	case 256:
		return 5
	default:
		panic("Only WotsW=4,16,256 are supported")
	}
}

// Returns the total number of WOTS+ chains
func (params *Params) WotsLen() uint32 {
	return params.WotsLen1() + params.WotsLen2()
}

// Returns the size of a WOTS+ signature
func (params *Params) WotsSignatureSize() uint32 {
	return params.WotsLen() * params.N
}

// Returns the maximum signature sequence number
func (params *Params) MaxSignatureSeqNo() uint64 {
	return (1 << params.FullHeight) - 1
}

// Returns the name and OID of this set of parameters, it is has them.
func (params *Params) LookupNameAndOid() (string, uint32) {
	for _, entry := range registry {
		if reflect.DeepEqual(entry.params, *params) {
			return entry.name, entry.oid
		}
	}
	return "", 0
}

// Looks up the name and oid of this set of parameters and returns whether
// any were found.
func (ctx *Context) ensureNameAndOidAreSet() bool {
	if ctx.name != nil {
		return true
	}
	var name2 string
	name2, ctx.oid = ctx.p.LookupNameAndOid()
	if name2 != "" {
		ctx.name = &name2
		return true
	}
	return false
}

// Returns the name of the XMSSMT instance and an empty string if it has
// no name.
func (ctx *Context) Name() string {
	if ctx.ensureNameAndOidAreSet() {
		return *ctx.name
	}
	return ""
}

// Returns the Oid of the XMSSMT instance and 0 if it has no Oid.
func (ctx *Context) Oid() uint32 {
	ctx.ensureNameAndOidAreSet()
	return ctx.oid
}

// Returns whether this is an XMSSMT instance (as opposed to XMSS)
func (ctx *Context) MT() bool {
	return ctx.mt
}

// Get parameters of an XMSS[MT] instance
func (ctx *Context) Params() Params {
	return ctx.p
}

// Returns the size of signatures of this XMSS[MT] instance
func (ctx *Context) SignatureSize() uint32 {
	return ctx.sigBytes
}

var registryNameLut map[string]regEntry
var registryOidLut map[uint32]regEntry
var registryOidMTLut map[uint32]regEntry

// Initializes algorithm lookup tables.
func init() {
	log = &dummyLogger{}
	registryNameLut = make(map[string]regEntry)
	registryOidLut = make(map[uint32]regEntry)
	registryOidMTLut = make(map[uint32]regEntry)
	for _, entry := range registry {
		registryNameLut[entry.name] = entry
		if entry.mt {
			registryOidMTLut[entry.oid] = entry
		} else {
			registryOidLut[entry.oid] = entry
		}
	}
}
