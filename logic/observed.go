package logic

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// Relay-observed source endpoints (tinc-style reflexive addresses).
//
// A node in the data path (notably a relay) sees each peer's REAL external
// WireGuard source ip:port. That is the correct hole-punch target even when the
// peer's own STUN self-report is wrong or stale: the self-report is the external
// mapping of a SEPARATE ephemeral STUN socket measured once at startup, which can
// differ from the persistent WG socket's mapping and goes stale after a network
// change. Reporting hosts push their observations to the server, which caches
// them here and substitutes them as the hole-punch candidate when building peer
// updates for OTHER peers.

type observedEntry struct {
	endpoint string
	seen     time.Time
}

var (
	observedMu  sync.RWMutex
	observedMap = map[string]map[string]observedEntry{} // reporterHostID -> peerPubKey -> entry
)

// observedTTL bounds how long an observation is trusted; a peer that roamed or
// went away stops being advertised once its observation goes stale.
const observedTTL = 3 * time.Minute

// SetObservedEndpoints records the endpoints a reporting host observes for its
// peers (peer-pubkey -> "ip:port").
func SetObservedEndpoints(reporterHostID string, eps map[string]string) {
	if len(eps) == 0 {
		return
	}
	now := time.Now()
	observedMu.Lock()
	defer observedMu.Unlock()
	m := observedMap[reporterHostID]
	if m == nil {
		m = map[string]observedEntry{}
		observedMap[reporterHostID] = m
	}
	for pk, ep := range eps {
		if ep == "" {
			continue
		}
		m[pk] = observedEntry{endpoint: ep, seen: now}
	}
}

// GetObservedEndpoint returns the freshest non-stale observed endpoint for
// peerPubKey. The relay's observation is preferred when relayHostID is set (it is
// the most reliable reporter — always in the data path); otherwise the freshest
// observation from any reporter is used. Returns "" when none is fresh.
func GetObservedEndpoint(peerPubKey, relayHostID string) string {
	observedMu.RLock()
	defer observedMu.RUnlock()
	now := time.Now()
	if relayHostID != "" {
		if m := observedMap[relayHostID]; m != nil {
			if e, ok := m[peerPubKey]; ok && now.Sub(e.seen) < observedTTL {
				return e.endpoint
			}
		}
	}
	var best observedEntry
	for _, m := range observedMap {
		if e, ok := m[peerPubKey]; ok && now.Sub(e.seen) < observedTTL {
			if best.seen.IsZero() || e.seen.After(best.seen) {
				best = e
			}
		}
	}
	return best.endpoint
}

// ParseObservedEndpoint splits an "ip:port" observation into a usable IP+port.
// Returns ok=false when the string is empty or malformed.
func ParseObservedEndpoint(s string) (net.IP, int, bool) {
	if s == "" {
		return nil, 0, false
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portStr)
	if err != nil || ip == nil || port <= 0 {
		return nil, 0, false
	}
	return ip, port, true
}
