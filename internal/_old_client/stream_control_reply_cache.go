// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	streamControlReplyTTL = 15 * time.Second
	streamControlReplyCap = 256
)

func (c *Client) cacheStreamControlReply(packet VpnProto.Packet) {
	if c == nil || !isCacheableStreamControlReply(packet.PacketType) || !packet.HasStreamID || !packet.HasSequenceNum || packet.StreamID == 0 {
		return
	}
	now := time.Now()
	c.streamControlReplyMu.Lock()
	defer c.streamControlReplyMu.Unlock()

	if len(c.streamControlReplies) >= streamControlReplyCap {
		c.pruneStreamControlRepliesLocked(now)
		if len(c.streamControlReplies) >= streamControlReplyCap {
			for key, cached := range c.streamControlReplies {
				delete(c.streamControlReplies, key)
				if cached.storedAt.Before(now) {
					break
				}
			}
		}
	}
	c.streamControlReplies[streamControlReplyKey{
		streamID:    packet.StreamID,
		sequenceNum: packet.SequenceNum,
		packetType:  packet.PacketType,
	}] = cachedStreamControlReply{
		packet:   packet,
		storedAt: now,
	}
}

func (c *Client) takeExpectedStreamControlReply(sentType uint8, streamID uint16, sequenceNum uint16) (VpnProto.Packet, bool) {
	if c == nil || streamID == 0 || sequenceNum == 0 {
		return VpnProto.Packet{}, false
	}
	now := time.Now()
	c.streamControlReplyMu.Lock()
	defer c.streamControlReplyMu.Unlock()
	c.pruneStreamControlRepliesLocked(now)

	for _, packetType := range expectedReplyPacketTypes(sentType) {
		key := streamControlReplyKey{
			streamID:    streamID,
			sequenceNum: sequenceNum,
			packetType:  packetType,
		}
		cached, ok := c.streamControlReplies[key]
		if !ok {
			continue
		}
		delete(c.streamControlReplies, key)
		return cached.packet, true
	}
	return VpnProto.Packet{}, false
}

func (c *Client) cachePackedStreamControlReplies(payload []byte) {
	if c == nil || len(payload) < arq.PackedControlBlockSize {
		return
	}
	arq.ForEachPackedControlBlock(payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if !isCacheableStreamControlReply(packetType) {
			return true
		}
		c.cacheStreamControlReply(VpnProto.Packet{
			PacketType:     packetType,
			StreamID:       streamID,
			HasStreamID:    streamID != 0,
			SequenceNum:    sequenceNum,
			HasSequenceNum: sequenceNum != 0,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		})
		return true
	})
}

func (c *Client) pruneStreamControlRepliesLocked(now time.Time) {
	if c == nil {
		return
	}
	cutoff := now.Add(-streamControlReplyTTL)
	for key, cached := range c.streamControlReplies {
		if cached.storedAt.Before(cutoff) {
			delete(c.streamControlReplies, key)
		}
	}
}

func expectedReplyPacketTypes(sentType uint8) []uint8 {
	switch sentType {
	case Enums.PACKET_STREAM_SYN:
		return []uint8{Enums.PACKET_STREAM_SYN_ACK}
	case Enums.PACKET_SOCKS5_SYN:
		return []uint8{
			Enums.PACKET_SOCKS5_SYN_ACK,
			Enums.PACKET_SOCKS5_CONNECT_FAIL,
			Enums.PACKET_SOCKS5_RULESET_DENIED,
			Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
			Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
			Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
			Enums.PACKET_SOCKS5_TTL_EXPIRED,
			Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
			Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
			Enums.PACKET_SOCKS5_AUTH_FAILED,
			Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		}
	case Enums.PACKET_STREAM_FIN:
		return []uint8{Enums.PACKET_STREAM_FIN_ACK}
	case Enums.PACKET_STREAM_RST:
		return []uint8{Enums.PACKET_STREAM_RST_ACK}
	default:
		return nil
	}
}

func isCacheableStreamControlReply(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_SOCKS5_SYN_ACK,
		Enums.PACKET_STREAM_FIN_ACK,
		Enums.PACKET_STREAM_RST_ACK:
		return true
	default:
		return isSOCKS5ErrorPacket(packetType)
	}
}
