// Package dialer resolves, authorizes, and dials proxy targets.
//
// Authorization is provided by the acl subpackage and applies equally to all
// transports. Target resolution is kept separate from transport dialing so UDP
// and UoT can reuse it later.
package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Del0n1x/caddyNaive/internal/dialer/acl"
	"github.com/Del0n1x/caddyNaive/internal/dialer/uot"
)

// Config controls target resolution and TCP dialing.
type Config struct {
	ACL       acl.Config
	Timeout   time.Duration
	KeepAlive time.Duration
}

// Dialer resolves and authorizes targets and establishes connections.
type Dialer struct {
	acl       *acl.Checker
	netDialer *net.Dialer
	timeout   time.Duration
}

// New creates a target dialer and compiles its ACL.
func New(config Config) (*Dialer, error) {
	checker, err := acl.New(config.ACL)
	if err != nil {
		return nil, err
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.KeepAlive <= 0 {
		config.KeepAlive = 30 * time.Second
	}
	return &Dialer{
		acl: checker,
		netDialer: &net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: config.KeepAlive,
		},
		timeout: config.Timeout,
	}, nil
}

// Dial resolves and authorizes hostPort, then opens the corresponding
// connection. The UoT v2 magic address creates a UDP-backed stream; all other
// targets are dialed as TCP.
func (d *Dialer) Dial(ctx context.Context, hostPort string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	if uot.IsMagic(host) {
		return d.dialUoT()
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, fmt.Errorf("invalid target port %q", portText)
	}

	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	ips, err := d.resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		conn, err := d.netDialer.DialContext(ctx, "tcp", address)
		if err == nil {
			return conn, nil
		}
		lastErr = fmt.Errorf("dial %s: %w", address, err)
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no allowed IP addresses for %s", host)
	}
	return nil, lastErr
}

func (d *Dialer) dialUoT() (net.Conn, error) {
	packetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	conn, err := uot.NewServerConn(packetConn, d.resolve)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	return conn, nil
}

// resolve applies port, domain, and IP policy and resolves the destination to
// the addresses that may be used. It is transport-independent and is the only
// place where ACL and DNS are consulted; both TCP and UoT call it.
func (d *Dialer) resolve(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	if host == "" {
		return nil, fmt.Errorf("target host is empty")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %d", port)
	}
	if !d.acl.AllowPort(port) {
		return nil, fmt.Errorf("port %d is not allowed", port)
	}

	// IP literals skip DNS and the domain gate.
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("IP zones are not supported")
		}
		ip = ip.Unmap()
		if !d.acl.AllowIP(ip) {
			return nil, fmt.Errorf("IP %s is denied", host)
		}
		return []netip.Addr{ip}, nil
	}

	if !d.acl.AllowDomain(host) {
		return nil, fmt.Errorf("domain %s is denied", host)
	}

	lookupHost := strings.TrimSuffix(host, ".")
	if lookupHost == "" {
		return nil, fmt.Errorf("target host is empty")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", lookupHost)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}

	seen := make(map[netip.Addr]struct{}, len(addresses))
	ips := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || !d.acl.AllowIP(address) {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		ips = append(ips, address)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no allowed IP addresses for %s", host)
	}
	return ips, nil
}
