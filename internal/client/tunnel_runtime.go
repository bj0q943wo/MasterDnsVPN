// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (tunnel_runtime.go) handles low-level UDP network operations,
// including sending DNS-encapsulated packets and receiving responses.
// ==============================================================================

package client

import (
	"errors"
	"net"
	"os"
	"time"

	"masterdnsvpn-go/internal/dnsparser"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// exchangeUDPQueryWithConn sends a UDP packet through the provided connection
// and waits for a response with a matching DNS transaction ID.
// It includes a mechanism to drain stale packets before sending.
func (c *Client) exchangeUDPQueryWithConn(conn *net.UDPConn, packet []byte, timeout time.Duration) ([]byte, error) {
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := packet[:2]

	// Drain any stale packets from the buffer (non-blocking)
	drainBuffer := c.getRuntimeUDPBuffer()
	for {
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			break
		}
		if _, err := conn.Read(drainBuffer); err != nil {
			break
		}
	}
	c.putRuntimeUDPBuffer(drainBuffer)

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, os.ErrDeadlineExceeded
		}

		buffer := c.getRuntimeUDPBuffer()
		n, err := conn.Read(buffer)
		if err != nil {
			c.putRuntimeUDPBuffer(buffer)
			return nil, err
		}

		if n >= 2 && buffer[0] == expectedID[0] && buffer[1] == expectedID[1] {
			return buffer[:n], nil
		}
		// Stale packet or from another request, continue reading until timeout
		c.putRuntimeUDPBuffer(buffer)
	}
}

// getUDPConn retrieves a UDP connection from the pool for the specified resolver.
// If no connection is available in the pool, it dials a new one.
func (c *Client) getUDPConn(resolverLabel string) (*net.UDPConn, error) {
	c.resolverConnsMu.Lock()
	pool, ok := c.resolverConns[resolverLabel]
	if !ok {
		pool = make(chan *net.UDPConn, 32)
		c.resolverConns[resolverLabel] = pool
	}
	c.resolverConnsMu.Unlock()

	select {
	case conn := <-pool:
		return conn, nil
	default:
		return dialUDPResolver(resolverLabel)
	}
}

// putUDPConn returns a UDP connection to the pool for the specified resolver.
// If the pool is full, the connection is closed.
func (c *Client) putUDPConn(resolverLabel string, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	c.resolverConnsMu.Lock()
	pool := c.resolverConns[resolverLabel]
	c.resolverConnsMu.Unlock()

	if pool == nil {
		_ = conn.Close()
		return
	}

	select {
	case pool <- conn:
	default:
		_ = conn.Close()
	}
}

// getRuntimeUDPBuffer retrieves a byte slice from the internal buffer pool.
// This is used to reduce allocations during high-frequency network operations.
func (c *Client) getRuntimeUDPBuffer() []byte {
	if c == nil {
		return make([]byte, runtimeUDPReadBufferSize())
	}
	buf, _ := c.udpBufferPool.Get().([]byte)
	if cap(buf) < runtimeUDPReadBufferSize() {
		return make([]byte, runtimeUDPReadBufferSize())
	}
	return buf[:runtimeUDPReadBufferSize()]
}

// putRuntimeUDPBuffer returns a byte slice to the internal buffer pool.
func (c *Client) putRuntimeUDPBuffer(buf []byte) {
	if c == nil || buf == nil {
		return
	}
	if cap(buf) < runtimeUDPReadBufferSize() {
		return
	}
	c.udpBufferPool.Put(buf[:runtimeUDPReadBufferSize()])
}

// dialUDPResolver resolves the resolver address and establishes a new UDP connection.
func dialUDPResolver(resolverLabel string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", resolverLabel)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

// normalizeTimeout ensures the timeout is positive, falling back to a default if necessary.
func normalizeTimeout(timeout time.Duration, fallback time.Duration) time.Duration {
	if timeout <= 0 {
		return fallback
	}
	return timeout
}

// runtimeUDPReadBufferSize defines the maximum size of the UDP read buffer.
func runtimeUDPReadBufferSize() int {
	return 65535
}

// udpQueryTransport wraps a UDP connection and a reusable buffer for queries.
type udpQueryTransport struct {
	conn   *net.UDPConn
	buffer []byte
}

// newUDPQueryTransport creates a new transport for UDP queries to the specified resolver.
func newUDPQueryTransport(resolverLabel string) (*udpQueryTransport, error) {
	conn, err := dialUDPResolver(resolverLabel)
	if err != nil {
		return nil, err
	}
	return &udpQueryTransport{
		conn:   conn,
		buffer: make([]byte, runtimeUDPReadBufferSize()),
	}, nil
}

// exchangeUDPQuery performs a synchronous UDP request-response cycle using the provided transport.
func exchangeUDPQuery(transport *udpQueryTransport, packet []byte, timeout time.Duration) ([]byte, error) {
	if transport == nil || transport.conn == nil {
		return nil, net.ErrClosed
	}
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := packet[:2]

	// Drain any stale packets from the buffer (non-blocking) before sending
	drainBuffer := make([]byte, 2048)
	for {
		if err := transport.conn.SetReadDeadline(time.Now()); err != nil {
			break
		}
		if _, err := transport.conn.Read(drainBuffer); err != nil {
			break
		}
	}

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)
	if err := transport.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := transport.conn.Write(packet); err != nil {
		return nil, err
	}

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, os.ErrDeadlineExceeded
		}

		n, err := transport.conn.Read(transport.buffer)
		if err != nil {
			return nil, err
		}

		if n >= 2 && transport.buffer[0] == expectedID[0] && transport.buffer[1] == expectedID[1] {
			return append([]byte(nil), transport.buffer[:n]...), nil
		}
		// Stale packet or from another request, continue reading until timeout
	}
}

// exchangeDNSOverConnection sends a DNS query and returns the extracted VPN packet.
func (c *Client) exchangeDNSOverConnection(conn Connection, query []byte, timeout time.Duration) (VpnProto.Packet, error) {
	udpConn, err := c.getUDPConn(conn.ResolverLabel)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	response, err := c.exchangeUDPQueryWithConn(udpConn, query, timeout)
	if err != nil {
		_ = udpConn.Close()
		return VpnProto.Packet{}, err
	}

	c.putUDPConn(conn.ResolverLabel, udpConn)

	packet, err := dnsparser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
	c.putRuntimeUDPBuffer(response)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	if !c.validateServerPacket(packet) {
		return VpnProto.Packet{}, errors.New("invalid VPN packet")
	}

	return packet, nil
}
