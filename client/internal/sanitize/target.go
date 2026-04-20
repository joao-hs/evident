package sanitize

import (
	"fmt"
	"net"
	"net/netip"
)

func TargetIP(targetIP string) (netip.Addr, error) {
	// If target IP is IPv4 or IPv6, use as is
	ip, err := netip.ParseAddr(targetIP)
	if err == nil {
		return ip, nil
	}

	// If target IP is a hostname, resolve to IP address
	ips, err := net.LookupIP(targetIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unable to resolve target IP or hostname: %v", err)
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("invalid target IP or hostname")
	}

	// default to the first resolved IP address
	parsedIP, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return netip.Addr{}, fmt.Errorf("unable to parse resolved IP address")
	}

	return parsedIP, nil
}

func TargetPort(targetPortStr string) (uint16, error) {
	var port uint16
	_, err := fmt.Sscanf(targetPortStr, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid target port: %v", targetPortStr)
	}
	return port, nil
}

func Target(targetStr string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(targetStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid target format: %v", err)
	}

	ip, err := TargetIP(host)
	if err != nil {
		return netip.AddrPort{}, err
	}

	portNum, err := TargetPort(port)
	if err != nil {
		return netip.AddrPort{}, err
	}

	return netip.AddrPortFrom(ip, portNum), nil
}
