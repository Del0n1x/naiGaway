// Package padding implements the NaiveProxy padding framing and bidirectional
// stream copy.
package padding

import (
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	// Header is sent by a client to opt in to padding and by a server to
	// advertise support.
	Header = "Padding"

	// TypeRequestHeader lists the padding types supported by the client, in
	// preference order.
	TypeRequestHeader = "Padding-Type-Request"

	// TypeReplyHeader advertises the selected padding protocol version.
	TypeReplyHeader = "Padding-Type-Reply"

	// TypeNone and TypeVariant1 are the padding protocol versions currently
	// implemented by NaiveProxy.
	TypeNone     = "0"
	TypeVariant1 = "1"

	firstPaddings = 8
)

// Negotiate selects the first client-supported padding version.
//
// Clients that predate padding-type-request only send Header, which implies
// variant 1. Clients that send TypeRequestHeader express their preference order;
// only versions 0 and 1 are currently defined.
func Negotiate(header http.Header, enabled bool) (usePadding bool, reply string) {
	if !enabled {
		return false, TypeNone
	}

	requested := header.Get(TypeRequestHeader)
	if requested != "" {
		for len(requested) > 0 {
			token := requested
			if index := strings.IndexByte(requested, ','); index >= 0 {
				token = requested[:index]
				requested = requested[index+1:]
			} else {
				requested = ""
			}
			switch strings.TrimSpace(token) {
			case TypeVariant1:
				return true, TypeVariant1
			case TypeNone:
				return false, TypeNone
			}
		}
		return false, TypeNone
	}

	if header.Get(Header) != "" {
		return true, TypeVariant1
	}
	return false, TypeNone
}

type mode uint8

const (
	modeNone mode = iota
	modeAdd
	modeRemove
)

var bufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, 64*1024)
		return &buffer
	},
}

// NewHeader creates the opaque, non-Huffman-coded value used to advertise
// padding support.
func NewHeader() string {
	const symbols = "!#$()+<>?@[]^`{}"
	length := rand.IntN(32) + 30
	var builder strings.Builder
	builder.Grow(length)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		builder.WriteByte(symbols[bits&0x0f])
		bits >>= 4
	}
	for i := 16; i < length; i++ {
		builder.WriteByte('~')
	}
	return builder.String()
}

// RawDualStream is the unpadded HTTP/1.1 path. Both endpoints are TCP
// connections, so io.Copy can use the platform's splice implementation instead
// of a userspace read/write loop.
func RawDualStream(target, client net.Conn) error {
	go func() {
		_, _ = io.Copy(target, client)
		if closer, ok := target.(closeWriter); ok {
			_ = closer.CloseWrite()
		}
	}()
	_, err := io.Copy(client, target)
	if closer, ok := client.(closeWriter); ok {
		_ = closer.CloseWrite()
	}
	return err
}

// DualStream copies bytes in both directions until the client-to-target side
// ends. Padding is applied only when both peers opted in.
func DualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer, enabled bool) error {
	if enabled {
		go copyStream(target, clientReader, modeRemove)
		return copyStream(clientWriter, target, modeAdd)
	}
	go copyStream(target, clientReader, modeNone)
	return copyStream(clientWriter, target, modeNone)
}

type closeWriter interface {
	CloseWrite() error
}

func copyStream(dst io.Writer, src io.Reader, copyMode mode) error {
	buffer := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(buffer)

	_, err := flushingCopy(dst, src, *buffer, copyMode)
	if closer, ok := dst.(closeWriter); ok {
		_ = closer.CloseWrite()
	}
	return err
}

func flushingCopy(dst io.Writer, src io.Reader, buffer []byte, copyMode mode) (written int64, err error) {
	var controller *http.ResponseController
	if writer, ok := dst.(http.ResponseWriter); ok {
		controller = http.NewResponseController(writer)
	}

	frames := 0
	var padding [256]byte

	for {
		var n int
		var readErr error

		switch {
		case copyMode == modeAdd && frames < firstPaddings:
			paddingSize := rand.IntN(256)
			maxPayload := len(buffer) - 3 - paddingSize
			if maxPayload <= 0 {
				return written, io.ErrShortBuffer
			}
			n, readErr = src.Read(buffer[3 : 3+maxPayload])
			if n > 0 {
				buffer[0] = byte(n / 256)
				buffer[1] = byte(n % 256)
				buffer[2] = byte(paddingSize)
				clear(buffer[3+n : 3+n+paddingSize])
				n += 3 + paddingSize
				frames++
			}

		case copyMode == modeRemove && frames < firstPaddings:
			if _, readErr = io.ReadFull(src, buffer[:3]); readErr != nil {
				if readErr == io.EOF {
					readErr = nil
				}
				return written, readErr
			}
			payloadSize := int(buffer[0])*256 + int(buffer[1])
			paddingSize := int(buffer[2])
			if payloadSize > len(buffer) {
				return written, io.ErrShortBuffer
			}
			if _, readErr = io.ReadFull(src, buffer[:payloadSize]); readErr != nil {
				return written, readErr
			}
			if paddingSize > 0 {
				if _, readErr = io.ReadFull(src, padding[:paddingSize]); readErr != nil {
					return written, readErr
				}
			}
			n = payloadSize
			frames++

		default:
			n, readErr = src.Read(buffer)
		}

		if n > 0 {
			writtenNow, writeErr := dst.Write(buffer[:n])
			if writtenNow > 0 {
				written += int64(writtenNow)
			}
			if writeErr != nil {
				return written, writeErr
			}
			if controller != nil {
				if err := controller.Flush(); err != nil {
					return written, err
				}
			}
			if n != writtenNow {
				return written, io.ErrShortWrite
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}
