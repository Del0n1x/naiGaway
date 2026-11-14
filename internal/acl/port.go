package acl

import (
	"fmt"
	"strconv"
	"strings"
)

type portRule struct {
	min   int
	max   int
	allow bool
}

func parsePortRule(subject string, allow bool) (portRule, error) {
	subject = strings.TrimSpace(subject)
	if subject == "*" {
		return portRule{min: 1, max: 65535, allow: allow}, nil
	}

	if strings.Contains(subject, "-") {
		parts := strings.SplitN(subject, "-", 2)
		start, err := parsePortNumber(parts[0])
		if err != nil {
			return portRule{}, err
		}
		end, err := parsePortNumber(parts[1])
		if err != nil {
			return portRule{}, err
		}
		if start > end {
			return portRule{}, fmt.Errorf("range start %d is greater than end %d", start, end)
		}
		return portRule{min: start, max: end, allow: allow}, nil
	}

	port, err := parsePortNumber(subject)
	if err != nil {
		return portRule{}, err
	}
	return portRule{min: port, max: port, allow: allow}, nil
}

func parsePortNumber(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return port, nil
}

func (r portRule) matches(port int) bool {
	return port >= r.min && port <= r.max
}
