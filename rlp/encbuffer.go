// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rlp

import (
	"encoding/binary"
	"io"
	"math/big"
	"sync"

	"github.com/holiman/uint256"
)

// The global encbuf pool.
var encBufferPool = sync.Pool{
	New: func() interface{} { return new(encbuf) },
}

func getEncBuffer() *encbuf {
	buf := encBufferPool.Get().(*encbuf)
	buf.reset()
	return buf
}

// makeBytes creates the encoder output.
func (buf *encbuf) makeBytes() []byte {
	out := make([]byte, buf.size())
	buf.copyTo(out)
	return out
}

func (buf *encbuf) copyTo(dst []byte) {
	strpos := 0
	pos := 0
	for _, head := range buf.lheads {
		// write string data before header
		n := copy(dst[pos:], buf.str[strpos:head.offset])
		pos += n
		strpos += n
		// write the header
		enc := head.encode(dst[pos:])
		pos += len(enc)
	}
	// copy string data after the last list header
	copy(dst[pos:], buf.str[strpos:])
}

// writeTo writes the encoder output to w.
func (buf *encbuf) writeTo(w io.Writer) (err error) {
	strpos := 0
	for _, head := range buf.lheads {
		// write string data before header
		if head.offset-strpos > 0 {
			n, err := w.Write(buf.str[strpos:head.offset])
			strpos += n
			if err != nil {
				return err
			}
		}
		// write the header
		enc := head.encode(buf.sizebuf[:])
		if _, err = w.Write(enc); err != nil {
			return err
		}
	}
	if strpos < len(buf.str) {
		// write string data after the last list header
		_, err = w.Write(buf.str[strpos:])
	}
	return err
}

// writeBool writes b as the integer 0 (false) or 1 (true).
func (buf *encbuf) writeBool(b bool) {
	if b {
		buf.str = append(buf.str, 0x01)
	} else {
		buf.str = append(buf.str, 0x80)
	}
}

func (buf *encbuf) writeUint64(i uint64) {
	if i == 0 {
		buf.str = append(buf.str, 0x80)
	} else if i < 128 {
		// fits single byte
		buf.str = append(buf.str, byte(i))
	} else {
		s := putint(buf.sizebuf[1:], i)
		buf.sizebuf[0] = 0x80 + byte(s)
		buf.str = append(buf.str, buf.sizebuf[:s+1]...)
	}
}

func (buf *encbuf) writeBytes(b []byte) {
	if len(b) == 1 && b[0] <= 0x7F {
		// fits single byte, no string header
		buf.str = append(buf.str, b[0])
	} else {
		buf.encodeStringHeader(len(b))
		buf.str = append(buf.str, b...)
	}
}

func (buf *encbuf) writeString(s string) {
	buf.writeBytes([]byte(s))
}

// wordBytes is the number of bytes in a big.Word
const wordBytes = (32 << (uint64(^big.Word(0)) >> 63)) / 8

// writeBigInt writes i as an integer.
func (buf *encbuf) writeBigInt(i *big.Int) {
	bitlen := i.BitLen()
	if bitlen <= 64 {
		buf.writeUint64(i.Uint64())
		return
	}
	// Integer is larger than 64 bits, encode from i.Bits().
	// The minimal byte length is bitlen rounded up to the next
	// multiple of 8, divided by 8.
	length := ((bitlen + 7) & -8) >> 3
	buf.encodeStringHeader(length)
	buf.str = append(buf.str, make([]byte, length)...)
	index := length
	bytesBuf := buf.str[len(buf.str)-length:]
	for _, d := range i.Bits() {
		for j := 0; j < wordBytes && index > 0; j++ {
			index--
			bytesBuf[index] = byte(d)
			d >>= 8
		}
	}
}

// writeUint256 writes z as an integer.
func (buf *encbuf) writeUint256(z *uint256.Int) {
	bitlen := z.BitLen()
	if bitlen <= 64 {
		buf.writeUint64(z.Uint64())
		return
	}
	nBytes := byte((bitlen + 7) / 8)
	var b [33]byte
	binary.BigEndian.PutUint64(b[1:9], z[3])
	binary.BigEndian.PutUint64(b[9:17], z[2])
	binary.BigEndian.PutUint64(b[17:25], z[1])
	binary.BigEndian.PutUint64(b[25:33], z[0])
	b[32-nBytes] = 0x80 + nBytes
	buf.str = append(buf.str, b[32-nBytes:]...)
}

func encBufferFromWriter(w io.Writer) *encbuf {
	switch w := w.(type) {
	case EncoderBuffer:
		return w.buf
	case *EncoderBuffer:
		return w.buf
	case *encbuf:
		return w
	default:
		return nil
	}
}

// EncoderBuffer is a buffer for incremental encoding.
//
// The zero value is NOT ready for use. To get a usable buffer,
// create it using NewEncoderBuffer or call Reset.
type EncoderBuffer struct {
	buf *encbuf
	dst io.Writer

	ownBuffer bool
}

// NewEncoderBuffer creates an encoder buffer.
func NewEncoderBuffer(dst io.Writer) EncoderBuffer {
	var w EncoderBuffer
	w.Reset(dst)
	return w
}

// Reset truncates the buffer and sets the output destination.
func (w *EncoderBuffer) Reset(dst io.Writer) {
	if w.buf != nil && !w.ownBuffer {
		panic("can't Reset derived EncoderBuffer")
	}

	// If the destination writer has an *encbuf, use it.
	// Note that w.ownBuffer is left false here.
	if dst != nil {
		if outer := encBufferFromWriter(dst); outer != nil {
			*w = EncoderBuffer{outer, nil, false}
			return
		}
	}

	// Get a fresh buffer.
	if w.buf == nil {
		w.buf = encBufferPool.Get().(*encbuf)
		w.ownBuffer = true
	}
	w.buf.reset()
	w.dst = dst
}

// Flush writes encoded RLP data to the output writer. This can only be called once.
// If you want to re-use the buffer after Flush, you must call Reset.
func (w *EncoderBuffer) Flush() error {
	var err error
	if w.dst != nil {
		err = w.buf.writeTo(w.dst)
	}
	// Release the internal buffer.
	if w.ownBuffer {
		encBufferPool.Put(w.buf)
	}
	*w = EncoderBuffer{}
	return err
}

// ToBytes returns the encoded bytes.
func (w *EncoderBuffer) ToBytes() []byte {
	return w.buf.makeBytes()
}

// AppendToBytes appends the encoded bytes to dst.
func (w *EncoderBuffer) AppendToBytes(dst []byte) []byte {
	size := w.buf.size()
	out := append(dst, make([]byte, size)...)
	w.buf.copyTo(out[len(dst):])
	return out
}

// Write appends b directly to the encoder output.
func (w EncoderBuffer) Write(b []byte) (int, error) {
	return w.buf.Write(b)
}

// WriteBool writes b as the integer 0 (false) or 1 (true).
func (w EncoderBuffer) WriteBool(b bool) {
	w.buf.writeBool(b)
}

// WriteUint64 encodes an unsigned integer.
func (w EncoderBuffer) WriteUint64(i uint64) {
	w.buf.writeUint64(i)
}

// WriteBigInt encodes a big.Int as an RLP string.
// Note: Unlike with Encode, the sign of i is ignored.
func (w EncoderBuffer) WriteBigInt(i *big.Int) {
	w.buf.writeBigInt(i)
}

// WriteUint256 encodes uint256.Int as an RLP string.
func (w EncoderBuffer) WriteUint256(i *uint256.Int) {
	w.buf.writeUint256(i)
}

// WriteBytes encodes b as an RLP string.
func (w EncoderBuffer) WriteBytes(b []byte) {
	w.buf.writeBytes(b)
}

// WriteString encodes s as an RLP string.
func (w EncoderBuffer) WriteString(s string) {
	w.buf.writeString(s)
}

// List starts a list. It returns an internal index. Call EndList with
// this index after encoding the content to finish the list.
func (w EncoderBuffer) List() int {
	w.buf.list()
	return len(w.buf.lheads) - 1
}

// ListEnd finishes the given list.
func (w EncoderBuffer) ListEnd(index int) {
	l := w.buf.lheads[index]
	w.buf.listEnd(l)
}
