package acl

import (
	"errors"
	"fmt"
	"strings"
)

type domainRule struct {
	any        bool
	domain     string
	subdomains bool
	allow      bool
}

func parseDomainRule(subject string, allow bool) (domainRule, error) {
	subject = strings.TrimSpace(subject)
	if subject == "*" {
		return domainRule{any: true, allow: allow}, nil
	}

	subject = normalizeDomain(subject)
	subdomains := strings.HasPrefix(subject, "*.")
	if subdomains {
		subject = subject[2:]
	}
	if err := validDomain(subject); err != nil {
		return domainRule{}, err
	}
	return domainRule{
		domain:     subject,
		subdomains: subdomains,
		allow:      allow,
	}, nil
}

func (r domainRule) matches(host string) bool {
	if r.any {
		return true
	}
	if r.subdomains {
		return strings.HasSuffix(host, "."+r.domain)
	}
	return host == r.domain
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

func normalizeHost(host string) string {
	return strings.TrimPrefix(normalizeDomain(host), ".")
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
