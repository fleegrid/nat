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

// Length get the length of IPPacket
func (p IPPacket) Length() (int, error) {
	switch p.Version() {
	case 4:
		{
			if len(p) < 4 {
				return -1, ErrIPPacketTooShort
			}
			return int(p[2])<<4 + int(p[3]), nil
		}
	case 6:
		{
			if len(p) < 6 {
				return -1, ErrIPPacketTooShort
			}
			return int(p[4])<<4 + int(p[5]) + IPv6PacketHeadLen, nil
		}
	default:
		{
			return -1, ErrIPPacketBadVersion
		}
	}
	return -1, nil
}

// ReadIPPacket read a IPPacket from a io.Reader
func ReadIPPacket(r io.Reader) (IPPacket, error) {
	// create a minimum header buf, 6 is enough for checking IP version and retrieving IPv4 and IPv6 length
	const hlen = 6
	p := make(IPPacket, hlen)
	// read the minimum header
	_, err := io.ReadFull(r, p)
	if err != nil {
		return nil, err
	}
	// retrieve packet length
	len, err := p.Length()
	if err != nil {
		return nil, err
	}
	// append size
	p = append(p, make(IPPacket, len-hlen)...)
	// read remaining
	_, err = io.ReadFull(r, p[hlen:])
	if err != nil {
		return nil, err
	}
	return p, nil
}
