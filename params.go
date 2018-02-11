package xmssmt

import (
	"fmt"
	"reflect"
)

type HashFunc uint32

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

// Entry in the registry of algorithms
type regEntry struct {
	name   string // name, eg. XMSSMT-SHA2_20/2_256
	mt     bool   // whether its XMSSMT (instead of XMSS)
	oid    uint32 // oid of the algorithm
	params Params // parameters of the algorithm
}

// Registry of named XMSS[MT] algorithms
var registry []regEntry = []regEntry{
	regEntry{"XMSSMT-SHA2_20/2_256", true, 0x00000001,
		Params{SHA2, 32, 20, 2, 16}},
	regEntry{"XMSSMT-SHA2_20/4_256", true, 0x00000002,
		Params{SHA2, 32, 20, 4, 16}},
	regEntry{"XMSSMT-SHA2_40/2_256", true, 0x00000003,
		Params{SHA2, 32, 40, 2, 16}},
	regEntry{"XMSSMT-SHA2_40/4_256", true, 0x00000004,
		Params{SHA2, 32, 40, 4, 16}},
	regEntry{"XMSSMT-SHA2_40/8_256", true, 0x00000005,
		Params{SHA2, 32, 40, 8, 16}},
	regEntry{"XMSSMT-SHA2_60/3_256", true, 0x00000006,
		Params{SHA2, 32, 60, 3, 16}},
	regEntry{"XMSSMT-SHA2_60/6_256", true, 0x00000007,
		Params{SHA2, 32, 60, 6, 16}},
	regEntry{"XMSSMT-SHA2_60/12_256", true, 0x00000008,
		Params{SHA2, 32, 60, 12, 16}},

	regEntry{"XMSSMT-SHA2_20/2_512", true, 0x00000009,
		Params{SHA2, 64, 20, 2, 16}},
	regEntry{"XMSSMT-SHA2_20/4_512", true, 0x0000000a,
		Params{SHA2, 64, 20, 4, 16}},
	regEntry{"XMSSMT-SHA2_40/2_512", true, 0x0000000b,
		Params{SHA2, 64, 40, 2, 16}},
	regEntry{"XMSSMT-SHA2_40/4_512", true, 0x0000000c,
		Params{SHA2, 64, 40, 4, 16}},
	regEntry{"XMSSMT-SHA2_40/8_512", true, 0x0000000d,
		Params{SHA2, 64, 40, 8, 16}},
	regEntry{"XMSSMT-SHA2_60/3_512", true, 0x0000000e,
		Params{SHA2, 64, 60, 3, 16}},
	regEntry{"XMSSMT-SHA2_60/6_512", true, 0x0000000f,
		Params{SHA2, 64, 60, 6, 16}},
	regEntry{"XMSSMT-SHA2_60/12_512", true, 0x00000010,
		Params{SHA2, 64, 60, 12, 16}},

	regEntry{"XMSSMT-SHAKE_20/2_256", true, 0x00000011,
		Params{SHAKE, 32, 20, 2, 16}},
	regEntry{"XMSSMT-SHAKE_20/4_256", true, 0x00000012,
		Params{SHAKE, 32, 20, 4, 16}},
	regEntry{"XMSSMT-SHAKE_40/2_256", true, 0x00000013,
		Params{SHAKE, 32, 40, 2, 16}},
	regEntry{"XMSSMT-SHAKE_40/4_256", true, 0x00000014,
		Params{SHAKE, 32, 40, 4, 16}},
	regEntry{"XMSSMT-SHAKE_40/8_256", true, 0x00000015,
		Params{SHAKE, 32, 40, 8, 16}},
	regEntry{"XMSSMT-SHAKE_60/3_256", true, 0x00000016,
		Params{SHAKE, 32, 60, 3, 16}},
	regEntry{"XMSSMT-SHAKE_60/6_256", true, 0x00000017,
		Params{SHAKE, 32, 60, 6, 16}},
	regEntry{"XMSSMT-SHAKE_60/12_256", true, 0x00000018,
		Params{SHAKE, 32, 60, 12, 16}},

	regEntry{"XMSSMT-SHAKE_20/2_512", true, 0x00000019,
		Params{SHAKE, 64, 20, 2, 16}},
	regEntry{"XMSSMT-SHAKE_20/4_512", true, 0x0000001a,
		Params{SHAKE, 64, 20, 4, 16}},
	regEntry{"XMSSMT-SHAKE_40/2_512", true, 0x0000001b,
		Params{SHAKE, 64, 40, 2, 16}},
	regEntry{"XMSSMT-SHAKE_40/4_512", true, 0x0000001c,
		Params{SHAKE, 64, 40, 4, 16}},
	regEntry{"XMSSMT-SHAKE_40/8_512", true, 0x0000001d,
		Params{SHAKE, 64, 40, 8, 16}},
	regEntry{"XMSSMT-SHAKE_60/3_512", true, 0x0000001e,
		Params{SHAKE, 64, 60, 3, 16}},
	regEntry{"XMSSMT-SHAKE_60/6_512", true, 0x0000001f,
		Params{SHAKE, 64, 60, 6, 16}},
	regEntry{"XMSSMT-SHAKE_60/12_512", true, 0x00000020,
		Params{SHAKE, 64, 60, 12, 16}},

	regEntry{"XMSS-SHA2_10_256", false, 0x00000001,
		Params{SHA2, 32, 10, 1, 16}},
	regEntry{"XMSS-SHA2_16_256", false, 0x00000002,
		Params{SHA2, 32, 16, 1, 16}},
	regEntry{"XMSS-SHA2_20_256", false, 0x00000003,
		Params{SHA2, 32, 20, 1, 16}},
	regEntry{"XMSS-SHA2_10_512", false, 0x00000004,
		Params{SHA2, 64, 10, 1, 16}},
	regEntry{"XMSS-SHA2_16_512", false, 0x00000005,
		Params{SHA2, 64, 16, 1, 16}},
	regEntry{"XMSS-SHA2_20_512", false, 0x00000006,
		Params{SHA2, 64, 20, 1, 16}},

	regEntry{"XMSS-SHAKE_10_256", false, 0x00000007,
		Params{SHAKE, 32, 10, 1, 16}},
	regEntry{"XMSS-SHAKE_16_256", false, 0x00000008,
		Params{SHAKE, 32, 16, 1, 16}},
	regEntry{"XMSS-SHAKE_20_256", false, 0x00000009,
		Params{SHAKE, 32, 20, 1, 16}},
	regEntry{"XMSS-SHAKE_10_512", false, 0x0000000a,
		Params{SHAKE, 64, 10, 1, 16}},
	regEntry{"XMSS-SHAKE_16_512", false, 0x0000000b,
		Params{SHAKE, 64, 16, 1, 16}},
	regEntry{"XMSS-SHAKE_20_512", false, 0x0000000c,
		Params{SHAKE, 64, 20, 1, 16}},
}

var registryNameLut map[string]regEntry
var registryOidLut map[uint32]regEntry
var registryOidMTLut map[uint32]regEntry

// Initializes algorithm lookup tables.
func init() {
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

// XMSS[MT] instance.
// Create one using NewContextFromName, NewContextFromOid or NewContext.
type Context struct {
	p            Params  // parameters.
	mt           bool    // true for XMSSMT; false for XMSS
	oid          uint32  // OID of this configuration, if it has any
	wotsLogW     uint8   // logarithm of the Winternitz parameter
	wotsLen1     uint32  // WOTS+ chains for message
	wotsLen2     uint32  // WOTS+ chains for checksum
	wotsLen      uint32  // total number of WOTS+ chains
	wotsSigBytes uint32  // length of WOTS+ signature
	treeHeight   uint32  // height of a subtree
	indexBytes   uint32  // size of an index
	sigBytes     uint32  // size of signature
	pkBytes      uint32  // size of public key
	skBytes      uint32  // size of secret key
	name         *string // name of algorithm
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

// Return new context for the given XMSS[MT] oid (and nil if it's unknown).
func NewContextFromOid(mt bool, oid uint32) *Context {
	var lut map[uint32]regEntry
	if mt {
		lut = registryOidMTLut
	} else {
		lut = registryOidLut
	}
	entry, ok := lut[oid]
	if ok {
		ctx, _ := NewContext(entry.params)
		return ctx
	} else {
		return nil
	}
}

// Return new context for the given XMSS[MT] algorithm name (and nil if the
// algorithm name is unknown).
func NewContextFromName(name string) *Context {
	params := ParamsFromName(name)
	if params == nil {
		return nil
	}
	ctx, _ := NewContext(*params)
	return ctx
}

// Creates a new context.
func NewContext(params Params) (ctx *Context, err error) {
	ctx = new(Context)
	ctx.p = params
	ctx.mt = (ctx.p.D == 1)

	if params.FullHeight%params.D != 0 {
		return nil, fmt.Errorf("D does not divide FullHeight")
	}

	ctx.treeHeight = params.FullHeight / params.D

	if params.WotsW != 16 {
		return nil, fmt.Errorf("Only WotsW=16 is supported at the moment")
	}

	if ctx.mt {
		ctx.indexBytes = (params.FullHeight + 7) / 8
	} else {
		ctx.indexBytes = 4
	}

	ctx.wotsLogW = 4
	ctx.wotsLen1 = 8 * params.N / uint32(ctx.wotsLogW)
	ctx.wotsLen2 = 3
	ctx.wotsLen = ctx.wotsLen1 + ctx.wotsLen2
	ctx.wotsSigBytes = ctx.wotsLen * params.N
	ctx.sigBytes = (ctx.indexBytes + params.N +
		params.D*ctx.wotsSigBytes + params.FullHeight*params.N)
	ctx.pkBytes = 2 * params.N
	ctx.skBytes = ctx.indexBytes + 4*params.N

	return
}

// Returns the name of the XMSSMT instance and an empty string if it has
// no name.
func (ctx *Context) Name() string {
	if ctx.name != nil {
		for _, entry := range registry {
			if reflect.DeepEqual(entry.params, ctx.p) {
				ctx.name = &entry.name
			}
		}
	}
	if ctx.name != nil {
		return *ctx.name
	}
	return ""
}

// List all named XMSS[MT] instances
func ListNames() (names []string) {
	names = make([]string, len(registry))
	for i, entry := range registry {
		names[i] = entry.name
	}
	return
}
