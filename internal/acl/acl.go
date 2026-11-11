// Package acl provides destination access-control checks for the proxy.
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

// Rule is a user-defined access control rule. Rules are evaluated in order,
// before the built-in private-range denials.
type Rule struct {
	Subjects []string `json:"subjects,omitempty"`
	Allow    bool     `json:"allow,omitempty"`
}

// Checker resolves and dials targets after applying ACL and port rules.
type Checker struct {
	rules        []rule
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
			checker.rules = append(checker.rules, compiled)
		}
	}
	for _, cidr := range defaultDeniedCIDRs {
		compiled, err := newRule(cidr, false)
		if err != nil {
			return nil, fmt.Errorf("invalid built-in ACL subject %q: %w", cidr, err)
		}
		checker.rules = append(checker.rules, compiled)
	}
	checker.rules = append(checker.rules, &allRule{allow: true})
	return checker, nil
}

// DialContext resolves the target and dials only addresses permitted by ACL.
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

	domainAllowed := false
	for _, rule := range c.rules {
		domainRule, ok := rule.(*domainRule)
		if !ok {
			continue
		}
		switch domainRule.tryMatch(nil, host) {
		case decisionDeny:
			return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("domain %s is denied", host))
		case decisionAllow:
			domainAllowed = true
		}
		if domainAllowed {
			break
		}
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("lookup %s: %w", host, err))
	}

	var lastErr error
	for _, address := range addresses {
		if !domainAllowed && !c.hostAllowed(host, address.IP) {
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

func (c *Checker) hostAllowed(hostname string, ip net.IP) bool {
	for _, rule := range c.rules {
		switch rule.tryMatch(ip, hostname) {
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
	domain = strings.TrimPrefix(domain, ".")
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
	if subject == "all" {
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
	if strings.HasPrefix(subject, "*.") {
		subdomainsAllowed = true
		subject = subject[2:]
	}
	if err := validDomain(subject); err != nil {
		return nil, fmt.Errorf("%q is not an IP, CIDR, or domain: %w", subject, err)
	}
	return &domainRule{
		domain:            subject,
		subdomainsAllowed: subdomainsAllowed,
		allow:             allow,
	}, nil
}

// ValidDomain validates a hostname used in configuration.
func ValidDomain(domain string) error {
	return validDomain(domain)
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
