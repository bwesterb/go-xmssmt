//go:generate enumer -type HashFunc

package xmssmt

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Hash function to use.
type HashFunc uint8

const (
	// SHA-256 for n≤32 and SHA-512 otherwise.  (From the RFC.)
	SHA2 HashFunc = iota

	// SHAKE-128 for n≤32 and SHAKE-256 otherwise.  (From the RFC.)
	SHAKE

	// SHAKE-256.  (From NIST SP 800-208.)
	SHAKE256
)

// Way to construct the various PRFs from the hash function.
type PrfConstruction uint8

const (
	// As described by RFC8391.
	RFC PrfConstruction = iota

	// As described by NIST SP 800-208.
	NIST
)

// Parameters of an XMSS[MT] instance
type Params struct {
	Func       HashFunc // which has function to use
	N          uint32   // security parameter: influences length of hashes
	FullHeight uint32   // full height of tree
	D          uint32   // number of subtrees; 1 for XMSS, >1 for XMSSMT

	// WOTS+ Winternitz parameter.  Only 4, 16 and 256 are supported.
	WotsW uint16

	// Method to use for construction of the PRFs.
	Prf PrfConstruction
}

func (p Params) String() string {
	wString := ""
	prfString := ""
	if p.Prf == NIST && p.N != 24 {
		prfString = "NIST"
	}
	if p.Prf == RFC && p.N == 24 {
		prfString = "RFC"
	}
	if p.WotsW != 16 {
		wString = fmt.Sprintf("_w%d", p.WotsW)
	}
	if p.D == 1 {
		return fmt.Sprintf("XMSS-%s_%d_%d%s%s",
			p.Func, p.FullHeight, p.N*8, wString, prfString)
	}
	return fmt.Sprintf("XMSSMT-%s_%d/%d_%d%s%s",
		p.Func, p.FullHeight, p.D, p.N*8, wString, prfString)
}

// Registry of named XMSS[MT] algorithms
var registry []regEntry = []regEntry{
	// From RFC8391.
	{"XMSSMT-SHA2_20/2_256", true, 0x00000001, Params{SHA2, 32, 20, 2, 16, RFC}},
	{"XMSSMT-SHA2_20/4_256", true, 0x00000002, Params{SHA2, 32, 20, 4, 16, RFC}},
	{"XMSSMT-SHA2_40/2_256", true, 0x00000003, Params{SHA2, 32, 40, 2, 16, RFC}},
	{"XMSSMT-SHA2_40/4_256", true, 0x00000004, Params{SHA2, 32, 40, 4, 16, RFC}},
	{"XMSSMT-SHA2_40/8_256", true, 0x00000005, Params{SHA2, 32, 40, 8, 16, RFC}},
	{"XMSSMT-SHA2_60/3_256", true, 0x00000006, Params{SHA2, 32, 60, 3, 16, RFC}},
	{"XMSSMT-SHA2_60/6_256", true, 0x00000007, Params{SHA2, 32, 60, 6, 16, RFC}},
	{"XMSSMT-SHA2_60/12_256", true, 0x00000008, Params{SHA2, 32, 60, 12, 16, RFC}},

	{"XMSSMT-SHA2_20/2_512", true, 0x00000009, Params{SHA2, 64, 20, 2, 16, RFC}},
	{"XMSSMT-SHA2_20/4_512", true, 0x0000000a, Params{SHA2, 64, 20, 4, 16, RFC}},
	{"XMSSMT-SHA2_40/2_512", true, 0x0000000b, Params{SHA2, 64, 40, 2, 16, RFC}},
	{"XMSSMT-SHA2_40/4_512", true, 0x0000000c, Params{SHA2, 64, 40, 4, 16, RFC}},
	{"XMSSMT-SHA2_40/8_512", true, 0x0000000d, Params{SHA2, 64, 40, 8, 16, RFC}},
	{"XMSSMT-SHA2_60/3_512", true, 0x0000000e, Params{SHA2, 64, 60, 3, 16, RFC}},
	{"XMSSMT-SHA2_60/6_512", true, 0x0000000f, Params{SHA2, 64, 60, 6, 16, RFC}},
	{"XMSSMT-SHA2_60/12_512", true, 0x00000010, Params{SHA2, 64, 60, 12, 16, RFC}},

	{"XMSSMT-SHAKE_20/2_256", true, 0x00000011, Params{SHAKE, 32, 20, 2, 16, RFC}},
	{"XMSSMT-SHAKE_20/4_256", true, 0x00000012, Params{SHAKE, 32, 20, 4, 16, RFC}},
	{"XMSSMT-SHAKE_40/2_256", true, 0x00000013, Params{SHAKE, 32, 40, 2, 16, RFC}},
	{"XMSSMT-SHAKE_40/4_256", true, 0x00000014, Params{SHAKE, 32, 40, 4, 16, RFC}},
	{"XMSSMT-SHAKE_40/8_256", true, 0x00000015, Params{SHAKE, 32, 40, 8, 16, RFC}},
	{"XMSSMT-SHAKE_60/3_256", true, 0x00000016, Params{SHAKE, 32, 60, 3, 16, RFC}},
	{"XMSSMT-SHAKE_60/6_256", true, 0x00000017, Params{SHAKE, 32, 60, 6, 16, RFC}},
	{"XMSSMT-SHAKE_60/12_256", true, 0x00000018, Params{SHAKE, 32, 60, 12, 16, RFC}},

	{"XMSSMT-SHAKE_20/2_512", true, 0x00000019, Params{SHAKE, 64, 20, 2, 16, RFC}},
	{"XMSSMT-SHAKE_20/4_512", true, 0x0000001a, Params{SHAKE, 64, 20, 4, 16, RFC}},
	{"XMSSMT-SHAKE_40/2_512", true, 0x0000001b, Params{SHAKE, 64, 40, 2, 16, RFC}},
	{"XMSSMT-SHAKE_40/4_512", true, 0x0000001c, Params{SHAKE, 64, 40, 4, 16, RFC}},
	{"XMSSMT-SHAKE_40/8_512", true, 0x0000001d, Params{SHAKE, 64, 40, 8, 16, RFC}},
	{"XMSSMT-SHAKE_60/3_512", true, 0x0000001e, Params{SHAKE, 64, 60, 3, 16, RFC}},
	{"XMSSMT-SHAKE_60/6_512", true, 0x0000001f, Params{SHAKE, 64, 60, 6, 16, RFC}},
	{"XMSSMT-SHAKE_60/12_512", true, 0x00000020, Params{SHAKE, 64, 60, 12, 16, RFC}},

	// From NIST SP 800-208.
	{"XMSSMT-SHA2_20/2_192", true, 0x00000021, Params{SHA2, 24, 20, 2, 16, NIST}},
	{"XMSSMT-SHA2_20/4_192", true, 0x00000022, Params{SHA2, 24, 20, 4, 16, NIST}},
	{"XMSSMT-SHA2_40/2_192", true, 0x00000023, Params{SHA2, 24, 40, 2, 16, NIST}},
	{"XMSSMT-SHA2_40/4_192", true, 0x00000024, Params{SHA2, 24, 40, 4, 16, NIST}},
	{"XMSSMT-SHA2_40/8_192", true, 0x00000025, Params{SHA2, 24, 40, 8, 16, NIST}},
	{"XMSSMT-SHA2_60/3_192", true, 0x00000026, Params{SHA2, 24, 60, 3, 16, NIST}},
	{"XMSSMT-SHA2_60/6_192", true, 0x00000027, Params{SHA2, 24, 60, 6, 16, NIST}},
	{"XMSSMT-SHA2_60/12_192", true, 0x00000028, Params{SHA2, 24, 60, 12, 16, NIST}},

	{"XMSSMT-SHAKE256_20/2_256", true, 0x00000029, Params{SHAKE256, 32, 20, 2, 16, RFC}},
	{"XMSSMT-SHAKE256_20/4_256", true, 0x0000002a, Params{SHAKE256, 32, 20, 4, 16, RFC}},
	{"XMSSMT-SHAKE256_40/2_256", true, 0x0000002b, Params{SHAKE256, 32, 40, 2, 16, RFC}},
	{"XMSSMT-SHAKE256_40/4_256", true, 0x0000002c, Params{SHAKE256, 32, 40, 4, 16, RFC}},
	{"XMSSMT-SHAKE256_40/8_256", true, 0x0000002d, Params{SHAKE256, 32, 40, 8, 16, RFC}},
	{"XMSSMT-SHAKE256_60/3_256", true, 0x0000002e, Params{SHAKE256, 32, 60, 3, 16, RFC}},
	{"XMSSMT-SHAKE256_60/6_256", true, 0x0000002f, Params{SHAKE256, 32, 60, 6, 16, RFC}},
	{"XMSSMT-SHAKE256_60/12_256", true, 0x00000030, Params{SHAKE256, 32, 60, 12, 16, RFC}},

	{"XMSSMT-SHAKE256_20/2_192", true, 0x00000031, Params{SHAKE256, 24, 20, 2, 16, NIST}},
	{"XMSSMT-SHAKE256_20/4_192", true, 0x00000032, Params{SHAKE256, 24, 20, 4, 16, NIST}},
	{"XMSSMT-SHAKE256_40/2_192", true, 0x00000033, Params{SHAKE256, 24, 40, 2, 16, NIST}},
	{"XMSSMT-SHAKE256_40/4_192", true, 0x00000034, Params{SHAKE256, 24, 40, 4, 16, NIST}},
	{"XMSSMT-SHAKE256_40/8_192", true, 0x00000035, Params{SHAKE256, 24, 40, 8, 16, NIST}},
	{"XMSSMT-SHAKE256_60/3_192", true, 0x00000036, Params{SHAKE256, 24, 60, 3, 16, NIST}},
	{"XMSSMT-SHAKE256_60/6_192", true, 0x00000037, Params{SHAKE256, 24, 60, 6, 16, NIST}},
	{"XMSSMT-SHAKE256_60/12_192", true, 0x00000038, Params{SHAKE256, 24, 60, 12, 16, NIST}},

	// From RFC8391.
	{"XMSS-SHA2_10_256", false, 0x00000001, Params{SHA2, 32, 10, 1, 16, RFC}},
	{"XMSS-SHA2_16_256", false, 0x00000002, Params{SHA2, 32, 16, 1, 16, RFC}},
	{"XMSS-SHA2_20_256", false, 0x00000003, Params{SHA2, 32, 20, 1, 16, RFC}},

	{"XMSS-SHA2_10_512", false, 0x00000004, Params{SHA2, 64, 10, 1, 16, RFC}},
	{"XMSS-SHA2_16_512", false, 0x00000005, Params{SHA2, 64, 16, 1, 16, RFC}},
	{"XMSS-SHA2_20_512", false, 0x00000006, Params{SHA2, 64, 20, 1, 16, RFC}},

	{"XMSS-SHAKE_10_256", false, 0x00000007, Params{SHAKE, 32, 10, 1, 16, RFC}},
	{"XMSS-SHAKE_16_256", false, 0x00000008, Params{SHAKE, 32, 16, 1, 16, RFC}},
	{"XMSS-SHAKE_20_256", false, 0x00000009, Params{SHAKE, 32, 20, 1, 16, RFC}},

	{"XMSS-SHAKE_10_512", false, 0x0000000a, Params{SHAKE, 64, 10, 1, 16, RFC}},
	{"XMSS-SHAKE_16_512", false, 0x0000000b, Params{SHAKE, 64, 16, 1, 16, RFC}},
	{"XMSS-SHAKE_20_512", false, 0x0000000c, Params{SHAKE, 64, 20, 1, 16, RFC}},

	// From NIST SP 800-208.
	{"XMSS-SHA2_10_192", false, 0x0000000d, Params{SHA2, 24, 10, 1, 16, NIST}},
	{"XMSS-SHA2_16_192", false, 0x0000000e, Params{SHA2, 24, 16, 1, 16, NIST}},
	{"XMSS-SHA2_20_192", false, 0x0000000f, Params{SHA2, 24, 20, 1, 16, NIST}},

	{"XMSS-SHAKE256_10_256", false, 0x00000010, Params{SHAKE256, 32, 10, 1, 16, RFC}},
	{"XMSS-SHAKE256_16_256", false, 0x00000011, Params{SHAKE256, 32, 16, 1, 16, RFC}},
	{"XMSS-SHAKE256_20_256", false, 0x00000012, Params{SHAKE256, 32, 20, 1, 16, RFC}},

	{"XMSS-SHAKE256_10_192", false, 0x00000013, Params{SHAKE256, 24, 10, 1, 16, NIST}},
	{"XMSS-SHAKE256_16_192", false, 0x00000014, Params{SHAKE256, 24, 16, 1, 16, NIST}},
	{"XMSS-SHAKE256_20_192", false, 0x00000015, Params{SHAKE256, 24, 20, 1, 16, NIST}},
}

// Encodes parameters in the reserved Oid space as follows (big endian).
//
//    8-bit magic         should be 0xEA
//    3-bit version       should be 0
//    1-bit prf           0 for RFC and 1 for NIST
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
	var prfCode uint32
	if params.N%8 != 0 {
		return errorf("N is not divisable by 8")
	}
	if params.N > 128 {
		return errorf("N is too large")
	}
	if params.Func > 2 {
		return errorf("Func is too large")
	}
	if params.FullHeight > 63 {
		return errorf("FullHeight is too large")
	}
	if params.D > 63 {
		return errorf("D is too large")
	}
	switch params.Prf {
	case RFC:
		prfCode = 0
	case NIST:
		prfCode = 1
	default:
		return errorf("Unknown Prf")
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
	val |= prfCode << 20
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
	version := (val >> 21) & ((1 << 3) - 1)
	if version != 0 {
		return errorf("Unsupported compressed parameters version")
	}
	comprN := (val >> 16) & ((1 << 4) - 1)
	wCode := (val >> 12) & ((1 << 2) - 1)
	rfcCode := (val >> 20) & 1
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
	if rfcCode == 0 {
		params.Prf = RFC
	} else {
		params.Prf = NIST
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

// Returns parameters for a named XMSS[MT] instance (and nil if there is no
// such algorithm listed in the RFC.)
func ParamsFromName(name string) *Params {
	entry, ok := registryNameLut[name]
	if ok {
		return &entry.params
	} else {
		return nil
	}
}

// Returns parameters for a XMSS[MT] instance (which might not be listed in
// the RFC.)
func ParamsFromName2(name string) (*Params, Error) {
	ret := ParamsFromName(name)
	if ret != nil {
		return ret, nil
	}
	return parseParamsFromName(name)
}

func parseParamsFromName(name string) (*Params, Error) {
	var ret Params
	var mt bool
	var err error

	bits := strings.SplitN(name, "-", 2)
	if len(bits) != 2 {
		return nil, errorf("Missing seperator between alg and params")
	}
	switch bits[0] {
	case "XMSS":
		mt = false
	case "XMSSMT":
		mt = true
	default:
		return nil, errorf("No such algorithm: %s", bits[0])
	}

	bits = strings.Split(bits[1], "_")
	switch bits[0] {
	case "SHA2":
		ret.Func = SHA2
	case "SHAKE":
		ret.Func = SHAKE
	case "SHAKE256":
		ret.Func = SHAKE256
	default:
		return nil, errorf("No such hash function: %s", bits[0])
	}

	if len(bits) < 3 || len(bits) > 5 {
		return nil, errorf("Expected three, four or five parameters, not %d",
			len(bits))
	}

	var unparsedFh string
	if strings.Contains(bits[1], "/") {
		if !mt {
			return nil, errorf("Can't have D parameter for XMSS")
		}
		fh_d := strings.SplitN(bits[1], "/", 2)
		unparsedFh = fh_d[0]
		d, err := strconv.Atoi(fh_d[1])
		if err != nil {
			return nil, wrapErrorf(err, "Can't parse D")
		}
		if d < 0 || d >= 1<<32 {
			return nil, errorf("D out of bounds")
		}
		ret.D = uint32(d)
	} else {
		if mt {
			return nil, errorf("Missing D parameter")
		}
		unparsedFh = bits[1]
		ret.D = 1
	}

	fh, err := strconv.Atoi(unparsedFh)
	if err != nil {
		return nil, wrapErrorf(err, "Can't parse FullHeight")
	}
	if fh < 0 || fh >= 1<<32 {
		return nil, errorf("FullHeight out of bounds")
	}
	ret.FullHeight = uint32(fh)

	n, err := strconv.Atoi(bits[2])
	if err != nil {
		return nil, wrapErrorf(err, "parse N")
	}
	if n < 0 || n > 1<<32 {
		return nil, errorf("N out of bounds")
	}
	ret.N = uint32(n) / 8

	if ret.N == 24 {
		ret.Prf = NIST
	}

	ret.WotsW = 16
	for i := 3; i < len(bits); i++ {
		if bits[i] == "NIST" {
			ret.Prf = NIST
			continue
		} else if bits[i] == "RFC" {
			ret.Prf = RFC
			continue
		} else if len(bits[i]) < 2 {
			return nil, errorf("Fourth or fifth parameter is too short")
		}
		if bits[i][0] != 'w' {
			return nil, errorf(
				"Expected 'w[...]', NIST or RFC for fourth or fifth parameter")
		}
		w, err := strconv.Atoi(bits[i][1:])
		if err != nil {
			return nil, wrapErrorf(err, "Failed to parse WotsW parameter")
		}
		if w < 0 || w >= 1<<16 {
			return nil, errorf("WotsW out of bounds")
		}
		ret.WotsW = uint16(w)
	}

	return &ret, nil
}

// List all named XMSS[MT] instances from RFC8391.
func ListNames() (names []string) {
	names = make([]string, len(registry))
	for i, entry := range registry {
		names[i] = entry.name
	}
	return
}

// List names of supported and useful XMSS[MT] instances (that might not be
// named in RFC8391 and thus might not be supported by other implementations.)
func ListNames2() (names []string) {
	var p Params
	add := func(fh, d uint32) {
		p.FullHeight = fh
		p.D = d
		names = append(names, p.String())
	}
	for _, h := range []HashFunc{SHA2, SHAKE, SHAKE256} {
		for _, w := range []uint16{4, 16, 256} {
			for _, n := range []uint32{16, 24, 32, 64} {
				if h == SHAKE256 && (n == 64 || n == 16) {
					continue
				}
				p.Func = h
				p.WotsW = w
				p.N = n
				add(20, 2)
				add(20, 4)
				add(40, 2)
				add(40, 4)
				add(40, 8)
				add(60, 3)
				add(60, 6)
				add(60, 12)
				add(10, 1)
				add(16, 1)
				add(20, 1)
			}
		}
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

// Returns whether this XMSS[MT] instance is listed in the NIST Special
// Publication.
func (ctx *Context) FromNIST() bool {
	ctx.ensureNameAndOidAreSet()
	if ctx.mt {
		return ctx.oid >= 0x21 && ctx.oid <= 0x38
	}
	return ctx.oid >= 0xd && ctx.oid <= 0x15
}

// Returns whether this XMSS[MT] instance is listed in the RFC (and thus should
// also be supported by other implementations).
func (ctx *Context) FromRFC() bool {
	ctx.ensureNameAndOidAreSet()
	if ctx.oid == 0 {
		return false
	}
	if ctx.mt {
		return ctx.oid <= 0x20
	}
	return ctx.oid <= 0xc
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
