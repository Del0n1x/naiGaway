package acl

import (
	"fmt"
	"net/netip"
	"strings"
)

type ipRule struct {
	any    bool
	prefix netip.Prefix
	allow  bool
}

func parseIPRule(subject string, allow bool) (ipRule, error) {
	subject = strings.TrimSpace(subject)
	if subject == "*" {
		return ipRule{any: true, allow: allow}, nil
	}

	if strings.Contains(subject, "/") {
		prefix, err := netip.ParsePrefix(subject)
		if err != nil {
			return ipRule{}, err
		}
		return ipRule{prefix: prefix.Masked(), allow: allow}, nil
	}

	addr, err := netip.ParseAddr(subject)
	if err != nil {
		return ipRule{}, fmt.Errorf("not an IP or CIDR: %w", err)
	}
	if addr.Zone() != "" {
		return ipRule{}, fmt.Errorf("IP zones are not supported")
	}
	addr = addr.Unmap()
	return ipRule{
		prefix: netip.PrefixFrom(addr, addr.BitLen()),
		allow:  allow,
	}, nil
}

func (r ipRule) matches(ip netip.Addr) bool {
	if r.any {
		return true
	}
	return r.prefix.Contains(ip)
}

var defaultDeniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}
