package nat

import (
	"errors"
	"io"
	"net"
)

// IPType enum for IP type
type IPType int

const (
	_ IPType = iota
	// SourceIP ip type for source
	SourceIP
	// DestinationIP ip type for source
	DestinationIP
)

// IPPacket represents a single IP packet
type IPPacket []byte

// IPv4PacketHeadLen IPv4 Packet minimum length
const IPv4PacketHeadLen = 20

// IPv6PacketHeadLen IPv6 Packet minimum length
const IPv6PacketHeadLen = 40

var (
	// ErrIPPacketTooShort IPPacket is too short for IPv4 or IPv6
	ErrIPPacketTooShort = errors.New("IPPacket is too short")
	// ErrIPPacketBadVersion IPPacket version not supported
	ErrIPPacketBadVersion = errors.New("IPPacket bad version")
	// ErrIPInvalid IP is invalid
	ErrIPInvalid = errors.New("IP invalid")
)

// Version returns IPPacket version, 4 or 6, 0 for empty IPPacket
func (p IPPacket) Version() int {
	if len(p) == 0 {
		return 0
	}
	return int(p[0] >> 4)
}

// GetIP get the source IP, nil for invalid IPPacket
func (p IPPacket) GetIP(t IPType) (net.IP, error) {
	switch p.Version() {
	case 4:
		{
			if len(p) < IPv4PacketHeadLen {
				return nil, ErrIPPacketTooShort
			}
			ip := make(net.IP, 4)
			if t == SourceIP {
				copy(ip, p[12:16])
			} else {
				copy(ip, p[16:20])
			}
			return ip, nil
		}
	case 6:
		{
			if len(p) < IPv6PacketHeadLen {
				return nil, ErrIPPacketTooShort
			}
			ip := make(net.IP, 16)
			if t == SourceIP {
				copy(ip, p[8:24])
			} else {
				copy(ip, p[24:40])
			}
			return ip, nil
		}
	default:
		{
			return nil, ErrIPPacketBadVersion
		}
	}
}

// SetIP set the source IP
func (p IPPacket) SetIP(t IPType, ip net.IP) error {
	switch p.Version() {
	case 4:
		{
			if len(p) < IPv4PacketHeadLen {
				return ErrIPPacketTooShort
			}
			if len(ip) < net.IPv4len {
				return ErrIPInvalid
			}
			if t == SourceIP {
				copy(p[12:16], ip[len(ip)-net.IPv4len:])
			} else {
				copy(p[16:20], ip[len(ip)-net.IPv4len:])
			}
			return nil
		}
	case 6:
		{
			if len(p) < IPv6PacketHeadLen {
				return ErrIPPacketTooShort
			}
			if len(ip) < net.IPv6len {
				return ErrIPInvalid
			}

			if t == SourceIP {
				copy(p[8:24], ip[len(ip)-net.IPv6len:])
			} else {
				copy(p[24:40], ip[len(ip)-net.IPv6len:])
			}
			return nil
		}
	default:
		{
			return ErrIPPacketBadVersion
		}
	}
}

// ReadIPPacket read a IPPacket from a io.Reader
func ReadIPPacket(r io.Reader) (IPPacket, error) {
	// create a header buf, 6 is enough for checking IP version and retrieving IPv4 and IPv6 length
	const hlen = 6
	h := make(IPPacket, hlen, hlen)
	// read 20
	_, err := r.Read(h)
	if err != nil {
		return nil, err
	}
	// check version
	switch h.Version() {
	case 4:
		{
			// calculate the packet length
			l := int(h[2])<<4 + int(h[3])
			if l < IPv4PacketHeadLen {
				return nil, ErrIPPacketTooShort
			}
			// create the real packet
			p := make(IPPacket, l, l)
			copy(p, h)
			// read the remaining
			_, err := r.Read(p[hlen:])
			if err != nil {
				return nil, err
			}
			return p, nil
		}
	case 6:
		{
			// calculate the packet length
			l := int(h[4])<<4 + int(h[5]) + IPv6PacketHeadLen
			// create the real packet
			p := make(IPPacket, l, l)
			copy(p, h)
			// read the remaining
			_, err := r.Read(p[hlen:])
			if err != nil {
				return nil, err
			}
			return p, nil
		}
	default:
		{
			return nil, ErrIPPacketBadVersion
		}
	}
	return nil, nil
}
