package logic

import (
	"context"
	"net"
	"strconv"

	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/servercfg"
	"gortc.io/stun"
)

// StartStunServer runs a minimal self-hosted STUN server so netclients can
// discover the public IP:port mapping of their WireGuard socket for NAT hole-
// punching, without depending on any third-party STUN service (e.g. Google's).
// It answers STUN binding requests with an XOR-MAPPED-ADDRESS of the packet
// source, which is exactly what gortc.io/stun clients expect.
//
// It listens on two consecutive ports (STUN_PORT and STUN_PORT+1). Two distinct
// STUN destinations let clients detect symmetric NAT: if the external port the
// NAT assigns differs between the two, hole-punching is impossible and the host
// must be relayed.
func StartStunServer(ctx context.Context) {
	port := servercfg.GetStunPort()
	go stunListener(ctx, port)
	go stunListener(ctx, port+1)
}

// stunListener answers STUN binding requests on a single UDP port.
func stunListener(ctx context.Context, port int) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		logger.Log(0, "failed to start STUN server on port "+strconv.Itoa(port)+":", err.Error())
		return
	}
	logger.Log(0, "STUN server listening on udp/"+strconv.Itoa(port))
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := req.Decode(); err != nil {
			continue
		}
		if req.Type != stun.BindingRequest {
			continue
		}
		resp, err := stun.Build(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: src.IP, Port: src.Port},
			stun.Fingerprint,
		)
		if err != nil {
			continue
		}
		_, _ = conn.WriteToUDP(resp.Raw, src)
	}
}
