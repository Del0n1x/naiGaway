// Package acl implements destination access control for the proxy.
//
// Port, domain, and IP rules form three independent gates. Rules within each
// gate are evaluated in declaration order, and the first matching rule decides
// that gate. A gate with no matching rule passes. A target is allowed only when
// all applicable gates pass.
//
// The domain gate applies to domain targets before DNS resolution. The IP gate
// applies to IP literals and to every address resolved from a domain.
package acl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Rule is an ordered ACL rule. Subjects are interpreted according to the
// section containing the rule.
type Rule struct {
	Subjects []string `json:"subjects"`
	Allow    bool     `json:"allow"`
}

// Config groups the three independent ACL gates.
type Config struct {
	Port   []Rule `json:"port,omitempty"`
	Domain []Rule `json:"domain,omitempty"`
	IP     []Rule `json:"ip,omitempty"`
}

// Checker resolves and dials targets after applying the ACL gates.
type Checker struct {
	portRules   []portRule
	domainRules []domainRule
	ipRules     []ipRule
	dial        func(context.Context, string, string) (net.Conn, error)
}

// New compiles ACL rules and appends the built-in private-range denials.
func New(config Config, dial func(context.Context, string, string) (net.Conn, error)) (*Checker, error) {
	if dial == nil {
		return nil, errors.New("acl dialer is required")
	}

	portRules, err := compileRules("port", config.Port, parsePortRule)
	if err != nil {
		return nil, err
	}
	domainRules, err := compileRules("domain", config.Domain, parseDomainRule)
	if err != nil {
		return nil, err
	}
	ipRules, err := compileRules("ip", config.IP, parseIPRule)
	if err != nil {
		return nil, err
	}

	for _, prefix := range defaultDeniedPrefixes {
		ipRules = append(ipRules, ipRule{prefix: prefix})
	}
	ipRules = append(ipRules, ipRule{any: true, allow: true})

	return &Checker{
		portRules:   portRules,
		domainRules: domainRules,
		ipRules:     ipRules,
		dial:        dial,
	}, nil
}

func compileRules[T any](section string, rules []Rule, parse func(string, bool) (T, error)) ([]T, error) {
	var compiled []T
	for _, rule := range rules {
		if len(rule.Subjects) == 0 {
			return nil, fmt.Errorf("%s ACL rule has no subjects", section)
		}
		for _, subject := range rule.Subjects {
			value, err := parse(subject, rule.Allow)
			if err != nil {
				return nil, fmt.Errorf("invalid %s ACL subject %q: %w", section, subject, err)
			}
			compiled = append(compiled, value)
		}
	}
	return compiled, nil
}

// DialContext resolves the target and dials only addresses allowed by every
// applicable ACL gate.
func (c *Checker) DialContext(ctx context.Context, network, hostPort string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("network %q is not supported", network))
	}

	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid target port %q", portText))
	}
	if !c.portAllowed(port) {
		return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("port %d is not allowed", port))
	}

	// IP literals skip the domain gate and go straight to the IP gate.
	if ip := net.ParseIP(host); ip != nil {
		if !c.ipAllowed(ip) {
			return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("IP %s is denied", host))
		}
		conn, err := c.dial(ctx, network, net.JoinHostPort(ip.String(), portText))
		if err != nil {
			return nil, caddyhttp.Error(http.StatusBadGateway, err)
		}
		return conn, nil
	}

	if !c.domainAllowed(host) {
		return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("domain %s is denied", host))
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, normalizeHost(host))
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("lookup %s: %w", host, err))
	}

	var lastErr error
	for _, address := range addresses {
		if !c.ipAllowed(address.IP) {
			continue
		}
		conn, err := c.dial(ctx, network, net.JoinHostPort(address.IP.String(), portText))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway, lastErr)
	}
	return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
}

func (c *Checker) portAllowed(port int) bool {
	for _, rule := range c.portRules {
		if rule.matches(port) {
			return rule.allow
		}
	}
	return true
}

func (c *Checker) domainAllowed(host string) bool {
	host = normalizeHost(host)
	for _, rule := range c.domainRules {
		if rule.matches(host) {
			return rule.allow
		}
	}
	return true
}

func (c *Checker) ipAllowed(ip net.IP) bool {
	for _, rule := range c.ipRules {
		if rule.matches(ip) {
			return rule.allow
		}
	}
	return false
}
