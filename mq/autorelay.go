package mq

import (
	"context"
	"fmt"
	"time"

	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
)

// StartAutoRelayReconciler periodically routes hosts detected behind a symmetric
// NAT (which cannot UDP hole-punch) through the admin-designated auto-relay node,
// and un-routes them once they are no longer symmetric. This is the community
// auto-relay fallback — the upstream auto-relay is EE/Pro-only.
func StartAutoRelayReconciler(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileAutoRelay()
		}
	}
}

func reconcileAutoRelay() {
	settings := logic.GetServerSettings()
	if !settings.AutoRelayEnabled || settings.AutoRelayNodeID == "" {
		return
	}
	relay, err := logic.GetNodeByID(settings.AutoRelayNodeID)
	if err != nil {
		logger.Log(1, "autorelay: designated relay node not found:", err.Error())
		return
	}
	// The designated node must act as a relay so peers can be attached to it.
	// Keep the models view consistent — peers.go computes relay routing from
	// models.Node, not from the schema layer.
	if !relay.IsRelay {
		relay.IsRelay = true
		relay.SetLastModified()
		if err := logic.UpsertNode(&relay); err != nil {
			logger.Log(1, "autorelay: failed to mark designated node as relay:", err.Error())
			return
		}
	}

	nodes, err := logic.GetNetworkNodes(relay.Network)
	if err != nil {
		return
	}

	// Desired relayed set: every non-gateway node currently reported as behind a
	// symmetric NAT (cannot hole-punch).
	desired := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if n.ID.String() == relay.ID.String() {
			continue
		}
		if n.IsRelay || n.IsIngressGateway || n.IsInternetGateway || n.IsAutoRelay {
			continue
		}
		host := logic.GetHostByNodeID(n.ID.String())
		if host == nil {
			continue
		}
		if host.NatType == models.NAT_Types.Symmetric {
			desired[n.ID.String()] = true
		}
	}

	current := map[string]bool{}
	for _, id := range relay.RelayedNodes {
		current[id] = true
	}
	if setsEqual(current, desired) {
		return
	}

	newList := make([]string, 0, len(desired))
	for id := range desired {
		newList = append(newList, id)
	}

	// Updates models.Node (IsRelayed/RelayedBy on each relayed node and
	// RelayedNodes on the relay) and the node cache that peer updates read from.
	logic.UpdateRelayNodes(relay.ID.String(), relay.RelayedNodes, newList)
	logger.Log(0, "autorelay: reconciled symmetric relayed set via", relay.ID.String(), "count:", fmt.Sprint(len(newList)))
	if err := PublishPeerUpdate(false); err != nil {
		logger.Log(0, "autorelay: peer update error:", err.Error())
	}
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
