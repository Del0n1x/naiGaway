// Package uot implements the server side of UDP over TCP v2.
//
// The protocol is the one used by sing-box when udp_over_tcp.version is 2:
// the client opens a CONNECT tunnel to MagicAddressV2, sends a request
// describing either a fixed destination or a multi-destination session, then
// exchanges length-prefixed UDP datagrams over the tunnel.
package uot

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
)

const (
	// MagicAddressV2 is the CONNECT authority used to select UoT v2.
	MagicAddressV2 = "sp.v2.udp-over-tcp.arpa"

	maxPacketSize = 65535

	atypIPv4   = 0x00
	atypIPv6   = 0x01
	atypDomain = 0x02
)

// UoT v2 request addresses use the standard SOCKS5 address types, while
// stream frames use the UoT-specific types above.
const (
	socksATYPIPv4   = 0x01
	socksATYPIPv6   = 0x04
	socksATYPDomain = 0x03
)

// IsMagic reports whether host selects UoT v2.
func IsMagic(host string) bool {
	return strings.EqualFold(host, MagicAddressV2)
}

func readAddress(r io.Reader, socks bool) (string, int, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}

	var host string
	switch {
	case socks && atyp[0] == socksATYPIPv4, !socks && atyp[0] == atypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(raw).String()
	case socks && atyp[0] == socksATYPIPv6, !socks && atyp[0] == atypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(raw).String()
	case socks && atyp[0] == socksATYPDomain, !socks && atyp[0] == atypDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", 0, err
		}
		host = string(raw)
	default:
		return "", 0, fmt.Errorf("unsupported UoT address type %#x", atyp[0])
	}

	var rawPort [2]byte
	if _, err := io.ReadFull(r, rawPort[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(rawPort[:])), nil
}

func readRequestAddress(r io.Reader) (string, int, error) {
	return readAddress(r, true)
}

func readFrameAddress(r io.Reader) (string, int, error) {
	return readAddress(r, false)
}

func writeAddress(w io.Writer, addr *net.UDPAddr, socks bool) error {
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return fmt.Errorf("invalid UDP address %s", addr)
	}
	ip = ip.Unmap()

	if socks {
		if ip.Is4() {
			if _, err := w.Write([]byte{socksATYPIPv4}); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte{socksATYPIPv6}); err != nil {
				return err
			}
		}
	} else {
		if ip.Is4() {
			if _, err := w.Write([]byte{atypIPv4}); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte{atypIPv6}); err != nil {
				return err
			}
		}
	}
	if _, err := w.Write(ip.AsSlice()); err != nil {
		return err
	}

	var rawPort [2]byte
	binary.BigEndian.PutUint16(rawPort[:], uint16(addr.Port))
	_, err := w.Write(rawPort[:])
	return err
}

func writeRequestAddress(w io.Writer, addr *net.UDPAddr) error {
	return writeAddress(w, addr, true)
}

func writeFrameAddress(w io.Writer, addr *net.UDPAddr) error {
	return writeAddress(w, addr, false)
}

func writeLength(w io.Writer, length int) error {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(length))
	_, err := w.Write(raw[:])
	return err
}
