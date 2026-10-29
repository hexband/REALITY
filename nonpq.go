package reality

import (
	"crypto/mlkem"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Compatibility with REALITY clients whose Client Hello has no X25519MLKEM768
// key share: sing-box, mihomo without "support-x25519mlkem768", Xray-core
// clients before v26.3.27 (uTLS Firefox 120 profile), and Xray-core clients
// with the edge, ios, qq or random fingerprints.
//
// The behaviour is selected by the XRAY_REALITY_NONPQ_CLIENTS environment
// variable, read once:
//
//	none    reject them (upstream behaviour)
//	legacy  accept them only from clients reporting a version below
//	        nonPQMaxClientVer, so current Xray-core clients still have to
//	        send X25519MLKEM768
//	all     select the key share as REALITY did before v26.9.8, whatever
//	        the client version: the first X25519 share, otherwise the X25519
//	        part of X25519MLKEM768
//
// When the variable is unset, empty or invalid, "legacy" is used if
// MinClientVer is set below nonPQMaxClientVer, and "none" otherwise.
//
// This only changes which Client Hellos get past the key share check.
// MinClientVer and MaxClientVer are checked as usual in every mode.

const nonPQClientsEnv = "XRAY_REALITY_NONPQ_CLIENTS"

type nonPQMode int

const (
	nonPQUnset nonPQMode = iota
	nonPQNone
	nonPQLegacy
	nonPQAll
)

var nonPQMaxClientVer = []byte{26, 3, 27}

var nonPQEnvMode = sync.OnceValue(func() nonPQMode {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(nonPQClientsEnv)))
	switch v {
	case "":
		return nonPQUnset
	case "none":
		return nonPQNone
	case "legacy":
		return nonPQLegacy
	case "all":
		return nonPQAll
	}
	fmt.Fprintf(os.Stderr, "REALITY: invalid %s=%q (want none, legacy or all), ignoring it\n", nonPQClientsEnv, v)
	return nonPQUnset
})

func (c *Config) nonPQMode() nonPQMode {
	if m := nonPQEnvMode(); m != nonPQUnset {
		return m
	}
	if c.MinClientVer != nil && Value(c.MinClientVer...) < Value(nonPQMaxClientVer...) {
		return nonPQLegacy
	}
	return nonPQNone
}

func nonPQClientVer(ver []byte) bool {
	return Value(ver...) < Value(nonPQMaxClientVer...)
}

func hasKeyShare(keyShares []keyShare, group CurveID) bool {
	for _, ks := range keyShares {
		if ks.group == group {
			return true
		}
	}
	return false
}

// legacyPeerPub selects the key share the way REALITY did before v26.9.8.
func legacyPeerPub(keyShares []keyShare) []byte {
	for _, ks := range keyShares {
		if ks.group == X25519 && len(ks.data) == 32 {
			return ks.data
		}
	}
	for _, ks := range keyShares {
		if ks.group == X25519MLKEM768 && len(ks.data) == mlkem.EncapsulationKeySize768+32 {
			return ks.data[mlkem.EncapsulationKeySize768:]
		}
	}
	return nil
}
