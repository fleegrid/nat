package nat

import (
	"errors"
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

// IPv4PacketMinLen IPv4 Packet minimum length
const IPv4PacketMinLen = 20

// IPv6PacketMinLen IPv6 Packet minimum length
const IPv6PacketMinLen = 40

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
			if len(p) < IPv4PacketMinLen {
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
			if len(p) < IPv6PacketMinLen {
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
			if len(p) < IPv4PacketMinLen {
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
			if len(p) < IPv6PacketMinLen {
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
