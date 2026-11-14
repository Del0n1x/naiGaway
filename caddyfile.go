package naiveproxy

import (
	"strings"

	"github.com/Del0n1x/naiGaway/internal/acl"
	"github.com/Del0n1x/naiGaway/internal/auth"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("naive_proxy", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("naive_proxy", httpcaddyfile.Before, "respond")
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	if err := handler.UnmarshalCaddyfile(helper.Dispenser); err != nil {
		return nil, err
	}
	return &handler, nil
}

// UnmarshalCaddyfile parses the naive_proxy directive.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "auth":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			if args[0] == "" {
				return d.Err("auth username cannot be empty")
			}
			if strings.ContainsRune(args[0], ':') {
				return d.Err("auth username cannot contain ':'")
			}
			if args[1] == "" {
				return d.Err("auth password cannot be empty")
			}
			h.Auth = append(h.Auth, auth.Credential{Username: args[0], Password: args[1]})

		case "padding":
			value, err := parseOptionalBool(d, true)
			if err != nil {
				return err
			}
			h.Padding = &value

		case "fast_open":
			value, err := parseOptionalBool(d, true)
			if err != nil {
				return err
			}
			h.FastOpen = &value

		case "idle_timeout":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			value, err := caddy.ParseDuration(args[0])
			if err != nil || value < 0 {
				return d.Errf("invalid idle_timeout %q", args[0])
			}
			h.IdleTimeout = caddy.Duration(value)

		case "dial_timeout":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			value, err := caddy.ParseDuration(args[0])
			if err != nil || value < 0 {
				return d.Errf("invalid dial_timeout %q", args[0])
			}
			h.DialTimeout = caddy.Duration(value)

		case "acl":
			if err := parseACL(d, &h.ACL); err != nil {
				return err
			}

		default:
			return d.Errf("unknown naive_proxy subdirective %q", d.Val())
		}
	}

	return nil
}

func parseACL(d *caddyfile.Dispenser, config *acl.Config) error {
	for sectionNesting := d.Nesting(); d.NextBlock(sectionNesting); {
		var rules *[]acl.Rule
		switch d.Val() {
		case "port":
			rules = &config.Port
		case "domain":
			rules = &config.Domain
		case "ip":
			rules = &config.IP
		default:
			return d.Errf("unknown acl section %q", d.Val())
		}

		for ruleNesting := d.Nesting(); d.NextBlock(ruleNesting); {
			var allow bool
			switch d.Val() {
			case "allow":
				allow = true
			case "deny":
				allow = false
			default:
				return d.Errf("unknown acl rule %q", d.Val())
			}

			subjects := d.RemainingArgs()
			if len(subjects) == 0 {
				return d.ArgErr()
			}
			*rules = append(*rules, acl.Rule{Subjects: subjects, Allow: allow})
		}
	}
	return nil
}

func parseOptionalBool(d *caddyfile.Dispenser, defaultValue bool) (bool, error) {
	args := d.RemainingArgs()
	switch len(args) {
	case 0:
		return defaultValue, nil
	case 1:
		switch strings.ToLower(args[0]) {
		case "on", "true", "yes", "1":
			return true, nil
		case "off", "false", "no", "0":
			return false, nil
		default:
			return false, d.Errf("expected on/off, got %q", args[0])
		}
	default:
		return false, d.ArgErr()
	}
}
