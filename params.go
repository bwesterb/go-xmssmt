package xmssmt

import (
	"reflect"
)

type HashFunc uint8

const (
	SHA2  HashFunc = 0
	SHAKE          = 1
)

// Parameters of an XMSS[MT] instance
type Params struct {
	Func       HashFunc // which has function to use
	N          uint32   // security parameter: influences length of hashes
	FullHeight uint32   // full height of tree
	D          uint32   // number of subtrees; 1 for XMSS, >1 for XMSSMT

	// WOTS+ Winternitz parameter.  Only 8, 16 and 256 are supported.
	WotsW uint16
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

// Returns the size of the subtrees for this parameter.
func (params *Params) BareSubTreeSize() int {
	height := (params.FullHeight / params.D) + 1
	return int(((1 << height) - 1) * params.N)
}

// Returns the size of the cached subtrees for this parameter.
func (params *Params) CachedSubTreeSize() int {
	// A cached subtree contains the merkle subtree and possibly
	// a WOTS+ signature of the substree above it.
	return params.BareSubTreeSize() + int(params.WotsSignatureSize())
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
	return 4
}

// Returns the number of  main WOTS+ chains
func (params *Params) WotsLen1() uint32 {
	return 8 * params.N / uint32(params.WotsLogW())
}

// Returns the number of WOTS+ checksum chains
func (params *Params) WotsLen2() uint32 {
	return 3
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

// Returns the name of the XMSSMT instance and an empty string if it has
// no name.
func (ctx *Context) Name() string {
	if ctx.name == nil {
		for _, entry := range registry {
			if reflect.DeepEqual(entry.params, ctx.p) {
				name2 := entry.name
				ctx.name = &name2
			}
		}
	}
	if ctx.name != nil {
		return *ctx.name
	}
	return ""
}

// Returns the Oid of the XMSSMT instance and 0 if it has no Oid.
func (ctx *Context) Oid() uint32 {
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
