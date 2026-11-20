// Package acl implements destination access control policy for the proxy.
//
// Port, domain, and IP rules form three independent gates. Rules within each
// gate are evaluated in declaration order, and the first matching rule decides
// that gate. Port and domain gates pass when no rule matches. The IP gate
// appends built-in private-range denials and a final allow-all rule, so it is
// fail-closed for private addresses by default. A target is allowed only when
// all applicable gates pass.
//
// The package is intentionally policy-only: it does not resolve DNS, dial
// connections, or know about HTTP status codes.
package acl

import (
	"fmt"
	"net/netip"
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

// Checker evaluates compiled ACL rules.
type Checker struct {
	portRules   []portRule
	domainRules []domainRule
	ipRules     []ipRule
}

// New compiles ACL rules and appends the built-in private-range denials.
func New(config Config) (*Checker, error) {
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

// AllowPort reports whether the port passes the port gate.
func (c *Checker) AllowPort(port int) bool {
	for _, rule := range c.portRules {
		if rule.matches(port) {
			return rule.allow
		}
	}
	return true
}

// AllowDomain reports whether the hostname passes the domain gate.
func (c *Checker) AllowDomain(host string) bool {
	host = normalizeHost(host)
	for _, rule := range c.domainRules {
		if rule.matches(host) {
			return rule.allow
		}
	}
	return true
}

// AllowIP reports whether the address passes the IP gate.
func (c *Checker) AllowIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, rule := range c.ipRules {
		if rule.matches(ip) {
			return rule.allow
		}
	}
	return false
}
