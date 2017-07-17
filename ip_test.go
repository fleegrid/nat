package nat

import (
	"net"
	"testing"
)

func TestIPPacket4(t *testing.T) {
	p := make(IPPacket, 20)
	p[0] = 0x45

	p[12] = 0xc0
	p[13] = 0xa8
	p[14] = 0x00
	p[15] = 0x01

	p[16] = 0xc0
	p[17] = 0xa8
	p[18] = 0x00
	p[19] = 0x02

	ip, err := p.GetIP(SourceIP)
	if err != nil {
		t.Errorf("Failed to get SourceIP: %v", err)
	}
	if ip.String() != "192.168.0.1" {
		t.Errorf("bad SourceIP: %v", ip.String())
	}

	ip, err = p.GetIP(DestinationIP)
	if err != nil {
		t.Errorf("Failed to get DestinationIP: %v", err)
	}
	if ip.String() != "192.168.0.2" {
		t.Errorf("bad destination ip: %v", ip.String())
	}

	err = p.SetIP(SourceIP, net.ParseIP("192.168.0.3"))
	if err != nil {
		t.Errorf("Failed to set source ip: %v", err)
	}
	if p[15] != 0x03 {
		t.Errorf("Failed to set source ip: %v", p[15])
	}

	err = p.SetIP(DestinationIP, net.ParseIP("192.168.0.4"))
	if err != nil {
		t.Errorf("Failed to set destination ip: %v", err)
	}
	if p[19] != 0x04 {
		t.Errorf("Failed to set destination ip: %v", p[19])
	}
}

func TestIPPacket6(t *testing.T) {
	p := make(IPPacket, 40)
	p[0] = 0x60

	p[8] = 0xfd
	p[23] = 0x01

	p[24] = 0xfd
	p[39] = 0x02

	ip, err := p.GetIP(SourceIP)
	if err != nil {
		t.Errorf("Failed to get SourceIP: %v", err)
	}
	if ip.String() != "fd00::1" {
		t.Errorf("bad SourceIP: %v", ip.String())
	}

	ip, err = p.GetIP(DestinationIP)
	if err != nil {
		t.Errorf("Failed to get DestinationIP: %v", err)
	}
	if ip.String() != "fd00::2" {
		t.Errorf("bad destination ip: %v", ip.String())
	}

	err = p.SetIP(SourceIP, net.ParseIP("fd00::3"))
	if err != nil {
		t.Errorf("Failed to set source ip: %v", err)
	}
	if p[23] != 0x03 {
		t.Errorf("Failed to set source ip: %v", p[23])
	}

	err = p.SetIP(DestinationIP, net.ParseIP("fd00::4"))
	if err != nil {
		t.Errorf("Failed to set destination ip: %v", err)
	}
	if p[39] != 0x04 {
		t.Errorf("Failed to set destination ip: %v", p[39])
	}

}
