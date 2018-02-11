package xmssmt

import (
	"fmt"
)

const (
	SHA2  = 0
	SHAKE = 1
)

// Paramaters of an XMSSMT instance.
// Create one using ParamsFromName or ParamsFromOid
type Params struct {
	MT           bool   // true for XMSSMT; false for XMSS
	Oid          uint32 // OID of this configuration
	Func         uint32 // hash function, either SHA2 or SHAKE
	N            uint32 // length of hash
	WotsW        uint16 // WOTS+ Winternitz parameter
	WotsLogW     uint8  // logarithm of the Winternitz parameter
	WotsLen1     uint32 // WOTS+ chains for message
	WotsLen2     uint32 // WOTS+ chains for checksum
	WotsLen      uint32 // total number of WOTS+ chains
	WotsSigBytes uint32 // length of WOTS+ signature
	FullHeight   uint32 // full height of the hypertree
	TreeHeight   uint32 // height of a subtree
	D            uint32 // number of subtrees
	IndexBytes   uint32 // size of an index
	SigBytes     uint32 // size of signature
	PkBytes      uint32 // size of public key
	SkBytes      uint32 // size of secret key
}

// Return parameters for the given XMSS[MT] algorithm name (and nil if the
// algorithm name is unknown).
func ParamsFromName(name string) *Params {
	mt, oid := OidFromName(name)
	if oid == 0 {
		return nil
	}
	return ParamsFromOid(mt, oid)
}

// Return parameters for the given XMSS[MT] OID  (and nil if OID is unknown).
func ParamsFromOid(mt bool, oid uint32) *Params {
	var params Params
	if mt {
		if oid < 0 || oid > 0x20 {
			return nil
		}

		if oid <= 0x10 {
			params.Func = SHA2
		} else {
			params.Func = SHAKE
		}

		if (oid <= 0x8) || ((0x11 <= oid) && (oid <= 0x18)) {
			params.N = 32
		} else {
			params.N = 64
		}

		if (oid == 0x1) || (oid == 0x2) || (oid == 0x9) || (oid == 0xa) ||
			(oid == 0x11) || (oid == 0x12) || (oid == 0x19) || (oid == 0x1a) {
			params.FullHeight = 20
		} else if (oid == 0x3) || (oid == 0x4) || (oid == 0x5) ||
			(oid == 0xb) || (oid == 0xc) || (oid == 0xd) ||
			(oid == 0x13) || (oid == 0x14) || (oid == 0x15) ||
			(oid == 0x1b) || (oid == 0x1c) || (oid == 0x1d) {
			params.FullHeight = 30
		} else {
			params.FullHeight = 60
		}

		if (oid == 0x1) || (oid == 0x3) || (oid == 0x9) ||
			(oid == 0xb) || (oid == 0x11) || (oid == 0x13) ||
			(oid == 0x19) || (oid == 0x1b) {
			params.D = 2
		} else if (oid == 0x2) || (oid == 0x4) || (oid == 0xa) ||
			(oid == 0xc) || (oid == 0x12) || (oid == 0x14) ||
			(oid == 0x1a) || (oid == 0x1c) {
			params.D = 4
		} else if (oid == 0x5) || (oid == 0xd) ||
			(oid == 0x15) || (oid == 0x1d) {
			params.D = 8
		} else if (oid == 0x6) || (oid == 0xe) ||
			(oid == 0x16) || (oid == 0x1e) {
			params.D = 3
		} else if (oid == 0x7) || (oid == 0xf) ||
			(oid == 0x17) || (oid == 0x1f) {
			params.D = 6
		} else {
			params.D = 12
		}

		params.IndexBytes = (params.FullHeight + 7) / 8
	} else { // !mt
		if oid < 0x1 || 0xc < oid {
			return nil
		}

		if oid <= 0x6 {
			params.Func = SHA2
		} else {
			params.Func = SHAKE
		}

		if (oid == 0x1) || (oid == 0x2) || (oid == 0x3) ||
			(oid == 0x7) || (oid == 0x8) || (oid == 0x9) {
			params.N = 32
		} else {
			params.N = 64
		}

		if (oid == 0x1) || (oid == 0x4) || (oid == 0x7) || (oid == 0xa) {
			params.FullHeight = 10
		} else if (oid == 0x2) || (oid == 0x5) || (oid == 0x8) || (oid == 0xb) {
			params.FullHeight = 16
		} else {
			params.FullHeight = 20
		}

		params.D = 1
		params.IndexBytes = 4
	}

	params.Oid = oid
	params.MT = mt
	params.TreeHeight = params.FullHeight / params.D
	params.WotsW = 16
	params.WotsLogW = 4
	params.WotsLen1 = 8 * params.N / uint32(params.WotsLogW)
	params.WotsLen2 = 3
	params.WotsLen = params.WotsLen1 + params.WotsLen2
	params.WotsSigBytes = params.WotsLen * params.N
	params.SigBytes = (params.IndexBytes + params.N +
		params.D*params.WotsSigBytes + params.FullHeight*
		params.N)
	params.PkBytes = 2 * params.N
	params.SkBytes = params.IndexBytes + 4*params.N

	return &params
}

// Return algorithm OID and whether it's multitree from the algorithm name.
// For instance XMSSMT-SHA2_20/2_256 is multitree and has OID 0x00000001.
// Returns OID 0 if the name is unknown.
func OidFromName(s string) (mt bool, oid uint32) {
	switch s {
	case "XMSSMT-SHA2_20/2_256":
		return true, 0x00000001
	case "XMSSMT-SHA2_20/4_256":
		return true, 0x00000002
	case "XMSSMT-SHA2_40/2_256":
		return true, 0x00000003
	case "XMSSMT-SHA2_40/4_256":
		return true, 0x00000004
	case "XMSSMT-SHA2_40/8_256":
		return true, 0x00000005
	case "XMSSMT-SHA2_60/3_256":
		return true, 0x00000006
	case "XMSSMT-SHA2_60/6_256":
		return true, 0x00000007
	case "XMSSMT-SHA2_60/12_256":
		return true, 0x00000008
	case "XMSSMT-SHA2_20/2_512":
		return true, 0x00000009
	case "XMSSMT-SHA2_20/4_512":
		return true, 0x0000000a
	case "XMSSMT-SHA2_40/2_512":
		return true, 0x0000000b
	case "XMSSMT-SHA2_40/4_512":
		return true, 0x0000000c
	case "XMSSMT-SHA2_40/8_512":
		return true, 0x0000000d
	case "XMSSMT-SHA2_60/3_512":
		return true, 0x0000000e
	case "XMSSMT-SHA2_60/6_512":
		return true, 0x0000000f
	case "XMSSMT-SHA2_60/12_512":
		return true, 0x00000010
	case "XMSSMT-SHAKE_20/2_256":
		return true, 0x00000011
	case "XMSSMT-SHAKE_20/4_256":
		return true, 0x00000012
	case "XMSSMT-SHAKE_40/2_256":
		return true, 0x00000013
	case "XMSSMT-SHAKE_40/4_256":
		return true, 0x00000014
	case "XMSSMT-SHAKE_40/8_256":
		return true, 0x00000015
	case "XMSSMT-SHAKE_60/3_256":
		return true, 0x00000016
	case "XMSSMT-SHAKE_60/6_256":
		return true, 0x00000017
	case "XMSSMT-SHAKE_60/12_256":
		return true, 0x00000018
	case "XMSSMT-SHAKE_20/2_512":
		return true, 0x00000019
	case "XMSSMT-SHAKE_20/4_512":
		return true, 0x0000001a
	case "XMSSMT-SHAKE_40/2_512":
		return true, 0x0000001b
	case "XMSSMT-SHAKE_40/4_512":
		return true, 0x0000001c
	case "XMSSMT-SHAKE_40/8_512":
		return true, 0x0000001d
	case "XMSSMT-SHAKE_60/3_512":
		return true, 0x0000001e
	case "XMSSMT-SHAKE_60/6_512":
		return true, 0x0000001f
	case "XMSSMT-SHAKE_60/12_512":
		return true, 0x00000020
	case "XMSS-SHA2_10_256":
		return false, 0x00000001
	case "XMSS-SHA2_16_256":
		return false, 0x00000002
	case "XMSS-SHA2_20_256":
		return false, 0x00000003
	case "XMSS-SHA2_10_512":
		return false, 0x00000004
	case "XMSS-SHA2_16_512":
		return false, 0x00000005
	case "XMSS-SHA2_20_512":
		return false, 0x00000006
	case "XMSS-SHAKE_10_256":
		return false, 0x00000007
	case "XMSS-SHAKE_16_256":
		return false, 0x00000008
	case "XMSS-SHAKE_20_256":
		return false, 0x00000009
	case "XMSS-SHAKE_10_512":
		return false, 0x0000000a
	case "XMSS-SHAKE_16_512":
		return false, 0x0000000b
	case "XMSS-SHAKE_20_512":
		return false, 0x0000000c
	default:
		return false, 0
	}
}

func (params *Params) Name() string {
	// TODO return actual name
	if params.MT {
		return fmt.Sprintf("XMSSMT oid %s", params.Oid)
	}
	return fmt.Sprintf("XMSS oid %d", params.Oid)
}
