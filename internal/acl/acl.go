// Package acl provides destination access-control checks for the proxy.
//
// Matching order is:
//
//  1. The target port is checked against the configured allow-list.
//  2. User domain rules are evaluated in declaration order. The first matching
//     rule decides; a domain allow bypasses per-IP checks.
//  3. User IP and "all" rules are evaluated in declaration order, followed by
//     the built-in private-range denials and a final allow-all.
//
// Within each phase the first matching rule wins. Because domain rules are a
// separate phase, an earlier "all" rule does not override a later domain deny
// for a domain target.
package acl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Rule is a user-defined access control rule. Domain rules run before IP rules
// for domain targets; within each phase, rules run in declaration order.
type Rule struct {
	Subjects []string `json:"subjects,omitempty"`
	Allow    bool     `json:"allow,omitempty"`
}

// Checker resolves and dials targets after applying ACL and port rules.
type Checker struct {
	domainRules  []*domainRule
	ipRules      []rule
	allowedPorts map[int]struct{}
	dial         func(context.Context, string, string) (net.Conn, error)
}

// New compiles ACL rules and appends defensive built-in denials. An empty port
// list permits every port.
func New(rules []Rule, allowedPorts []int, dial func(context.Context, string, string) (net.Conn, error)) (*Checker, error) {
	if dial == nil {
		return nil, errors.New("acl dialer is required")
	}

	checker := &Checker{dial: dial}
	if len(allowedPorts) > 0 {
		checker.allowedPorts = make(map[int]struct{}, len(allowedPorts))
		for _, port := range allowedPorts {
			if port <= 0 || port > 65535 {
				return nil, fmt.Errorf("allowed port %d is outside 1-65535", port)
			}
			checker.allowedPorts[port] = struct{}{}
		}
	}

	for _, rule := range rules {
		if len(rule.Subjects) == 0 {
			return nil, errors.New("ACL rule has no subjects")
		}
		for _, subject := range rule.Subjects {
			compiled, err := newRule(subject, rule.Allow)
			if err != nil {
				return nil, fmt.Errorf("invalid ACL subject %q: %w", subject, err)
			}
			if domainRule, ok := compiled.(*domainRule); ok {
				checker.domainRules = append(checker.domainRules, domainRule)
				continue
			}
			checker.ipRules = append(checker.ipRules, compiled)
		}
	}
	for _, cidr := range defaultDeniedCIDRs {
		compiled, err := newRule(cidr, false)
		if err != nil {
			return nil, fmt.Errorf("invalid built-in ACL subject %q: %w", cidr, err)
		}
		checker.ipRules = append(checker.ipRules, compiled)
	}
	checker.ipRules = append(checker.ipRules, &allRule{allow: true})
	return checker, nil
}

// DialContext resolves the target and dials only addresses permitted by ACL.
// For domain targets, a matching domain allow bypasses per-IP checks; otherwise
// every resolved address must pass ipAllowed.
func (c *Checker) DialContext(ctx context.Context, network, hostPort string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("network %q is not supported", network))
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}
	if !c.portAllowed(port) {
		return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("port %s is not allowed", port))
	}

	// IP targets are common for local services and avoid a resolver round trip.
	if ip := net.ParseIP(host); ip != nil {
		if !c.ipAllowed(ip) {
			return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("IP %s is denied", host))
		}
		conn, err := c.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			return nil, caddyhttp.Error(http.StatusBadGateway, err)
		}
		return conn, nil
	}

	// Domain rules run before DNS resolution, so an explicit deny can reject a
	// hostname without touching the network.
	domainAllowed := false
	switch c.domainDecision(host) {
	case decisionDeny:
		return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("domain %s is denied", host))
	case decisionAllow:
		domainAllowed = true
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("lookup %s: %w", host, err))
	}

	var lastErr error
	for _, address := range addresses {
		if !domainAllowed && !c.ipAllowed(address.IP) {
			continue
		}
		conn, err := c.dial(ctx, network, net.JoinHostPort(address.IP.String(), port))
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

// domainDecision evaluates only user domain rules. Domain rules run before IP
// rules, so a domain allow may bypass the built-in private-range denials.
func (c *Checker) domainDecision(host string) decision {
	for _, rule := range c.domainRules {
		if decision := rule.tryMatch(nil, host); decision != decisionNoMatch {
			return decision
		}
	}
	return decisionNoMatch
}

// ipAllowed evaluates user IP/all rules, then the built-in denials, then the
// final allow-all. Domain rules are not part of this phase.
func (c *Checker) ipAllowed(ip net.IP) bool {
	for _, rule := range c.ipRules {
		switch rule.tryMatch(ip, "") {
		case decisionDeny:
			return false
		case decisionAllow:
			return true
		}
	}
	return false
}

func (c *Checker) portAllowed(port string) bool {
	number, err := strconv.Atoi(port)
	if err != nil || number <= 0 || number > 65535 {
		return false
	}
	if len(c.allowedPorts) == 0 {
		return true
	}
	_, ok := c.allowedPorts[number]
	return ok
}

type decision uint8

const (
	decisionAllow decision = iota
	decisionDeny
	decisionNoMatch
)

type rule interface {
	tryMatch(ip net.IP, domain string) decision
}

type ipRule struct {
	network net.IPNet
	allow   bool
}

func (r *ipRule) tryMatch(ip net.IP, _ string) decision {
	if !r.network.Contains(ip) {
		return decisionNoMatch
	}
	if r.allow {
		return decisionAllow
	}
	return decisionDeny
}

type domainRule struct {
	domain            string
	subdomainsAllowed bool
	allow             bool
}

func (r *domainRule) tryMatch(_ net.IP, domain string) decision {
	domain = strings.TrimPrefix(normalizeDomain(domain), ".")
	if domain != r.domain && !(r.subdomainsAllowed && strings.HasSuffix(domain, "."+r.domain)) {
		return decisionNoMatch
	}
	if r.allow {
		return decisionAllow
	}
	return decisionDeny
}

type allRule struct {
	allow bool
}

func (r *allRule) tryMatch(net.IP, string) decision {
	if r.allow {
		return decisionAllow
	}
	return decisionDeny
}

var defaultDeniedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

func newRule(subject string, allow bool) (rule, error) {
	normalized := normalizeDomain(subject)
	if normalized == "all" {
		return &allRule{allow: allow}, nil
	}

	_, network, err := net.ParseCIDR(subject)
	if err != nil {
		ip := net.ParseIP(subject)
		switch {
		case ip.To4() != nil:
			_, network, err = net.ParseCIDR(subject + "/32")
		case ip.To16() != nil:
			_, network, err = net.ParseCIDR(subject + "/128")
		}
	}
	if err == nil {
		return &ipRule{network: *network, allow: allow}, nil
	}

	subdomainsAllowed := false
	if strings.HasPrefix(normalized, "*.") {
		subdomainsAllowed = true
		normalized = normalized[2:]
	}
	if err := validDomain(normalized); err != nil {
		return nil, fmt.Errorf("%q is not an IP, CIDR, or domain: %w", subject, err)
	}
	return &domainRule{
		domain:            normalized,
		subdomainsAllowed: subdomainsAllowed,
		allow:             allow,
	}, nil
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

func validDomain(domain string) error {
	if domain == "" {
		return errors.New("domain cannot be empty")
	}
	for i := 0; i < len(domain); i++ {
		char := domain[i]
		if 'a' <= char && char <= 'z' ||
			'A' <= char && char <= 'Z' ||
			'0' <= char && char <= '9' ||
			char == '-' || char == '.' || char == '_' {
			continue
		}
		return fmt.Errorf("character %q is not allowed", char)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return errors.New("empty domain label")
		}
		if len(label) > 63 {
			return errors.New("domain label is too long")
		}
	}
	return nil
}
