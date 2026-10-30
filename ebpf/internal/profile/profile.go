// Package profile parses the WireGuard wire-type profile.
package profile

import (
	"fmt"
	"strconv"
	"strings"
)

// Profile maps canonical types to on-wire types.
type Profile struct {
	// Wire[i] is the wire type for canonical type i+1.
	Wire [4]uint32
}

func (p Profile) validate() error {
	seen := make(map[uint32]struct{}, len(p.Wire))
	for i, v := range p.Wire {
		if v == 0 {
			return fmt.Errorf("wire type for canonical %d is zero", i+1)
		}
		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate wire type %d", v)
		}
		seen[v] = struct{}{}
	}
	return nil
}

// ParseWire parses "X,Y,Z,W" into a Profile.
func ParseWire(s string) (Profile, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return Profile{}, fmt.Errorf("wire needs 4 comma-separated values, got %d", len(parts))
	}
	var p Profile
	for i, part := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil {
			return Profile{}, fmt.Errorf("wire[%d]: %w", i, err)
		}
		p.Wire[i] = uint32(v)
	}
	if err := p.validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// ParsePorts parses "a,b,c" into ports. Empty input returns nil.
func ParsePorts(s string) ([]uint16, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []uint16
	for _, part := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", part, err)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}
