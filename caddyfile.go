package naiveproxy

import (
	"bufio"
	"fmt"
	"os"
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
		case "hosts":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.Hosts = caddyhttp.MatchHost(args)

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

		case "probe_resistance":
			args := d.RemainingArgs()
			if len(args) > 1 {
				return d.ArgErr()
			}
			if len(args) == 1 {
				h.ProbeResistanceDomain = args[0]
			}

		case "hide_ip":
			if len(d.RemainingArgs()) != 0 {
				return d.ArgErr()
			}
			h.HideIP = true

		case "hide_via":
			if len(d.RemainingArgs()) != 0 {
				return d.ArgErr()
			}
			h.HideVia = true

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

		case "max_idle_conns":
			value, err := parseIntArg(d)
			if err != nil {
				return err
			}
			h.MaxIdleConns = value

		case "max_idle_conns_per_host":
			value, err := parseIntArg(d)
			if err != nil {
				return err
			}
			h.MaxIdleConnsPerHost = value

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
				case "allow_file":
					if len(args) != 1 {
						return d.ArgErr()
					}
					subjects, err := readACLFile(args[0])
					if err != nil {
						return err
					}
					h.ACL = append(h.ACL, acl.Rule{Subjects: subjects, Allow: true})
					continue
				case "deny_file":
					if len(args) != 1 {
						return d.ArgErr()
					}
					subjects, err := readACLFile(args[0])
					if err != nil {
						return err
					}
					h.ACL = append(h.ACL, acl.Rule{Subjects: subjects, Allow: false})
					continue
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

func parseIntArg(d *caddyfile.Dispenser) (int, error) {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return 0, d.ArgErr()
	}
	value, err := strconv.Atoi(args[0])
	if err != nil {
		return 0, d.Errf("expected an integer, got %q", args[0])
	}
	return value, nil
}

func readACLFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subjects []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		subjects = append(subjects, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(subjects) == 0 {
		return nil, fmt.Errorf("ACL file %s contains no subjects", path)
	}
	return subjects, nil
}
