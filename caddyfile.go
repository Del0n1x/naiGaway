package naiveproxy

import (
	"strconv"
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
	httpcaddyfile.RegisterDirectiveOrder("naive_proxy", httpcaddyfile.Before, "reverse_proxy")
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

		case "allow_ports":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			ports := make([]int, 0, len(args))
			for _, arg := range args {
				port, err := strconv.Atoi(arg)
				if err != nil || port <= 0 || port > 65535 {
					return d.Errf("invalid port %q", arg)
				}
				ports = append(ports, port)
			}
			h.AllowedPorts = ports

		case "acl":
			for nested := d.Nesting(); d.NextBlock(nested); {
				directive := d.Val()
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}

				var allow bool
				switch directive {
				case "allow":
					allow = true
				case "deny":
					allow = false
				default:
					return d.Errf("unknown acl directive %q", directive)
				}
				h.ACL = append(h.ACL, acl.Rule{Subjects: args, Allow: allow})
			}

		default:
			return d.Errf("unknown naive_proxy subdirective %q", d.Val())
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
