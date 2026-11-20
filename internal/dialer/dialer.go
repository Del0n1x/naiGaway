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

// DialTCP resolves and authorizes hostPort, then dials the first reachable
// allowed TCP address.
func (d *Dialer) DialTCP(ctx context.Context, hostPort string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	endpoint, err := d.resolve(ctx, hostPort)
	if err != nil {
		return nil, err
	}
	return d.dialAny(ctx, "tcp", endpoint)
}

type endpoint struct {
	host string
	port int
	ips  []netip.Addr
}

// resolve parses hostPort, applies the ACL, resolves the target, and filters
// the result to the addresses allowed by the IP gate.
func (d *Dialer) resolve(ctx context.Context, hostPort string) (endpoint, error) {
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return endpoint{}, err
	}
	if host == "" {
		return endpoint{}, fmt.Errorf("target host is empty")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return endpoint{}, fmt.Errorf("invalid target port %q", portText)
	}
	if !d.acl.AllowPort(port) {
		return endpoint{}, fmt.Errorf("port %d is not allowed", port)
	}

	resolved := endpoint{host: host, port: port}

	// IP literals skip DNS and the domain gate.
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return endpoint{}, fmt.Errorf("IP zones are not supported")
		}
		ip = ip.Unmap()
		if !d.acl.AllowIP(ip) {
			return endpoint{}, fmt.Errorf("IP %s is denied", host)
		}
		resolved.ips = []netip.Addr{ip}
		return resolved, nil
	}

	if !d.acl.AllowDomain(host) {
		return endpoint{}, fmt.Errorf("domain %s is denied", host)
	}

	lookupHost := strings.TrimSuffix(host, ".")
	if lookupHost == "" {
		return endpoint{}, fmt.Errorf("target host is empty")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", lookupHost)
	if err != nil {
		return endpoint{}, fmt.Errorf("lookup %s: %w", host, err)
	}

	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || !d.acl.AllowIP(address) {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		resolved.ips = append(resolved.ips, address)
	}
	if len(resolved.ips) == 0 {
		return endpoint{}, fmt.Errorf("no allowed IP addresses for %s", host)
	}
	return resolved, nil
}

// dialAny establishes a connection to one of the target's authorized
// addresses. Keeping the network separate lets a future DialUDP reuse the same
// resolution and authorization path.
func (d *Dialer) dialAny(ctx context.Context, network string, endpoint endpoint) (net.Conn, error) {
	if len(endpoint.ips) == 0 {
		return nil, fmt.Errorf("no authorized IP addresses for %s", endpoint.host)
	}

	var lastErr error
	for _, ip := range endpoint.ips {
		address := net.JoinHostPort(ip.String(), strconv.Itoa(endpoint.port))
		conn, err := d.netDialer.DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		lastErr = fmt.Errorf("dial %s: %w", address, err)
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no allowed IP addresses for %s", endpoint.host)
	}
	return nil, lastErr
}
