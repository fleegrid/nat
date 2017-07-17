package nat

import (
	"errors"
	"net"
)

var (
	// ErrOutOfIPs Net has ran out of IPs
	ErrOutOfIPs = errors.New("out of IPs")
	// ErrBadGatewayIP GatewayIP is not in CIDR
	ErrBadGatewayIP = errors.New("bad gateway IP")
)

// Net a simple Net that manages a subnet and automatically maps IPs
type Net struct {
	*net.IPNet
	GatewayIP net.IP
	usedIPs   map[string]bool
}

// NewNet creates a new Net instance, with given size
func NewNet(gip net.IP, ipnet *net.IPNet) (*Net, error) {
	if !ipnet.Contains(gip) {
		return nil, ErrBadGatewayIP
	}
	return &Net{
		IPNet:     ipnet,
		GatewayIP: gip,
		usedIPs: map[string]bool{
			gip.String(): true,
		},
	}, nil
}

// NewNetFromCIDR creates a new Net instance from CIDR string
func NewNetFromCIDR(cidr string) (*Net, error) {
	gip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return NewNet(gip, ipnet)
}

// Mark make a ip as already taken
func (n *Net) Mark(ip net.IP) {
	if n.Contains(ip) {
		n.usedIPs[ip.String()] = true
	}
}

// Take take a virtual IP from Net's subnet
func (n *Net) Take() (net.IP, error) {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	for {
		increaseIP(ip)
		if !n.Contains(ip) {
			return nil, ErrOutOfIPs
		}
		k := ip.String()
		if !n.usedIPs[k] {
			n.usedIPs[k] = true
			return ip, nil
		}
	}
}

// Remove remove a virtual IP by id
func (n *Net) Remove(ip net.IP) {
	delete(n.usedIPs, ip.String())
}

// increase a IP address
func increaseIP(ip net.IP) {
	for i := len(ip); i > 0; i-- {
		ip[i-1]++
		if ip[i-1] != 0 {
			return
		}
	}
}
