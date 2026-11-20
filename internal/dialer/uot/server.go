package uot

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ResolveFunc resolves and authorizes a destination to IP addresses.
type ResolveFunc func(ctx context.Context, host string, port int) ([]netip.Addr, error)

type pipeAddr struct{}

func (pipeAddr) Network() string { return "uot" }
func (pipeAddr) String() string  { return "uot" }

// serverConn adapts a UDP packet connection to a net.Conn carrying UoT v2
// frames. Writes parse client frames and send UDP; reads encode received UDP
// packets back into frames.
type serverConn struct {
	packetConn net.PacketConn
	resolve    ResolveFunc

	inputReader  *io.PipeReader
	inputWriter  *io.PipeWriter
	outputReader *io.PipeReader
	outputWriter *io.PipeWriter

	ready chan struct{}
	done  chan struct{}
	once  sync.Once

	isConnect   bool
	destination *net.UDPAddr
}

// NewServerConn creates a UoT v2 server connection over packetConn.
func NewServerConn(packetConn net.PacketConn, resolve ResolveFunc) (net.Conn, error) {
	if packetConn == nil {
		return nil, errors.New("UoT packet connection is required")
	}
	if resolve == nil {
		return nil, errors.New("UoT resolver is required")
	}

	c := &serverConn{
		packetConn: packetConn,
		resolve:    resolve,
		ready:      make(chan struct{}),
		done:       make(chan struct{}),
	}
	c.inputReader, c.inputWriter = io.Pipe()
	c.outputReader, c.outputWriter = io.Pipe()

	go c.loopInput()
	go c.loopOutput()
	return c, nil
}

func (c *serverConn) Read(p []byte) (int, error) {
	return c.outputReader.Read(p)
}

func (c *serverConn) Write(p []byte) (int, error) {
	return c.inputWriter.Write(p)
}

func (c *serverConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.inputReader.Close()
		c.inputWriter.Close()
		c.outputReader.Close()
		c.outputWriter.Close()
		c.packetConn.Close()
	})
	return nil
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.packetConn.LocalAddr()
}

func (c *serverConn) RemoteAddr() net.Addr {
	return pipeAddr{}
}

func (c *serverConn) SetDeadline(time.Time) error {
	return nil
}

func (c *serverConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *serverConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *serverConn) loopInput() {
	defer c.Close()

	var isConnect [1]byte
	if _, err := io.ReadFull(c.inputReader, isConnect[:]); err != nil {
		return
	}
	if isConnect[0] > 1 {
		return
	}
	c.isConnect = isConnect[0] == 1

	host, port, err := readRequestAddress(c.inputReader)
	if err != nil {
		return
	}
	if c.isConnect {
		c.destination, err = c.udpDestination(host, port)
		if err != nil {
			return
		}
	}

	close(c.ready)

	buffer := make([]byte, maxPacketSize)
	for {
		var destination *net.UDPAddr
		if c.isConnect {
			destination = c.destination
		} else {
			host, port, err := readFrameAddress(c.inputReader)
			if err != nil {
				return
			}
			destination, err = c.udpDestination(host, port)
			if err != nil {
				return
			}
		}

		var rawLength [2]byte
		if _, err := io.ReadFull(c.inputReader, rawLength[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(rawLength[:]))
		if _, err := io.ReadFull(c.inputReader, buffer[:length]); err != nil {
			return
		}
		if _, err := c.packetConn.WriteTo(buffer[:length], destination); err != nil {
			return
		}
	}
}

func (c *serverConn) loopOutput() {
	defer c.Close()

	select {
	case <-c.ready:
	case <-c.done:
		return
	}

	buffer := make([]byte, maxPacketSize)
	for {
		length, addr, err := c.packetConn.ReadFrom(buffer)
		if err != nil {
			return
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		if c.isConnect {
			if !sameUDPAddr(udpAddr, c.destination) {
				continue
			}
			if err := writeLength(c.outputWriter, length); err != nil {
				return
			}
		} else {
			if err := writeFrameAddress(c.outputWriter, udpAddr); err != nil {
				return
			}
			if err := writeLength(c.outputWriter, length); err != nil {
				return
			}
		}
		if _, err := c.outputWriter.Write(buffer[:length]); err != nil {
			return
		}
	}
}

func (c *serverConn) udpDestination(host string, port int) (*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := c.resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no resolved destination")
	}
	return &net.UDPAddr{
		IP:   net.IP(ips[0].AsSlice()),
		Port: port,
	}, nil
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}
