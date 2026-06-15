package mq

import (
	"context"
	"time"

	"github.com/gravitl/netmaker/db"
	dbtypes "github.com/gravitl/netmaker/db/types"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
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
	dctx := db.WithContext(context.TODO())

	relay := &schema.Node{ID: settings.AutoRelayNodeID}
	if err := relay.Get(dctx, dbtypes.WithAllPreloads()); err != nil {
		logger.Log(1, "autorelay: designated relay node not found:", err.Error())
		return
	}
	// The relay must already be a gateway (set up once by the admin) so that
	// relayed clients can be attached to it.
	if !relay.IsGateway {
		logger.Log(1, "autorelay: designated node", relay.ID, "is not a gateway/relay yet")
		return
	}

	nodes, err := logic.GetNetworkNodes(relay.Network.Name)
	if err != nil {
		return
	}

	changed := false
	for i := range nodes {
		nodeID := nodes[i].ID.String()
		if nodeID == relay.ID {
			continue
		}
		host := logic.GetHostByNodeID(nodeID)
		if host == nil {
			continue
		}
		symmetric := host.NatType == models.NAT_Types.Symmetric

		sn := &schema.Node{ID: nodeID}
		if err := sn.Get(dctx, dbtypes.WithAllPreloads()); err != nil {
			continue
		}
		// Never relay a gateway/relay node itself.
		if sn.IsGateway {
			continue
		}
		relayedByThis := sn.RelayedByNodeID != nil && *sn.RelayedByNodeID == relay.ID

		switch {
		case symmetric && sn.RelayedByNodeID == nil:
			id := relay.ID
			sn.RelayedByNodeID = &id
			if err := sn.AssignGateway(dctx); err == nil {
				logger.Log(0, "autorelay: relaying symmetric node", nodeID, "via", relay.ID)
				changed = true
			} else {
				logger.Log(1, "autorelay: assign error for", nodeID, err.Error())
			}
		case !symmetric && relayedByThis:
			sn.RelayedByNodeID = nil
			if err := sn.UnassignGateway(dctx); err == nil {
				logger.Log(0, "autorelay: un-relaying node", nodeID, "(no longer symmetric)")
				changed = true
			} else {
				logger.Log(1, "autorelay: unassign error for", nodeID, err.Error())
			}
		}
	}

	if changed {
		if err := PublishPeerUpdate(false); err != nil {
			logger.Log(0, "autorelay: peer update error:", err.Error())
		}
	}
}
