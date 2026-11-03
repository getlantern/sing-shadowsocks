package shadowaead

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

// https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
const (
	MaxPacketSize          = 16*1024 - 1
	PacketLengthBufferSize = 2
)

const (
	// Overhead
	// crypto/cipher.gcmTagSize
	// golang.org/x/crypto/chacha20poly1305.Overhead
	Overhead = 16
)

// largeBufferSize fits a 2022 writer buffer (65535-byte chunks), which is
// larger than the biggest size class of buf.Get.
const largeBufferSize = 65535 + PacketLengthBufferSize + Overhead*2

var largeBufferPool = sync.Pool{New: func() any { return new([largeBufferSize]byte) }}

func getBuffer(size int) []byte {
	if size <= 65536 {
		return buf.Get(size)
	}
	if size <= largeBufferSize {
		return largeBufferPool.Get().(*[largeBufferSize]byte)[:size]
	}
	return make([]byte, size)
}

func putBuffer(buffer []byte) {
	if cap(buffer) == largeBufferSize {
		largeBufferPool.Put((*[largeBufferSize]byte)(buffer[:largeBufferSize]))
		return
	}
	_ = buf.Put(buffer)
}

// Reader holds its chunk buffer only while decrypted data is cached, so an
// idle connection blocked on the next length chunk holds no large buffer.
type Reader struct {
	upstream io.Reader
	cipher   cipher.AEAD
	buffer   []byte
	size     int // 0 when the caller owns buffer
	nonce    []byte
	index    int
	cached   int
	header   [PacketLengthBufferSize + Overhead]byte
}

func NewReader(upstream io.Reader, cipher cipher.AEAD, maxPacketSize int) *Reader {
	return &Reader{
		upstream: upstream,
		cipher:   cipher,
		size:     maxPacketSize + Overhead,
		nonce:    make([]byte, cipher.NonceSize()),
	}
}

func NewRawReader(upstream io.Reader, cipher cipher.AEAD, buffer []byte, nonce []byte) *Reader {
	return &Reader{
		upstream: upstream,
		cipher:   cipher,
		buffer:   buffer,
		nonce:    nonce,
	}
}

func (r *Reader) acquire() {
	if r.buffer == nil {
		r.buffer = getBuffer(r.size)
	}
}

func (r *Reader) release() {
	if r.size > 0 && r.buffer != nil && r.cached == 0 {
		putBuffer(r.buffer)
		r.buffer = nil
		r.index = 0
	}
}

func (r *Reader) Upstream() any {
	return r.upstream
}

func (r *Reader) readLength() (int, error) {
	_, err := io.ReadFull(r.upstream, r.header[:])
	if err != nil {
		return 0, err
	}
	return r.openLength(r.header[:])
}

func (r *Reader) openLength(lengthChunk []byte) (int, error) {
	_, err := r.cipher.Open(r.header[:0], r.nonce, lengthChunk, nil)
	if err != nil {
		return 0, err
	}
	increaseNonce(r.nonce)
	return int(binary.BigEndian.Uint16(r.header[:PacketLengthBufferSize])), nil
}

// readPayload reads and decrypts a chunk of length bytes into the buffer and
// caches it.
func (r *Reader) readPayload(length int) error {
	r.acquire()
	end := length + Overhead
	_, err := io.ReadFull(r.upstream, r.buffer[:end])
	if err == nil {
		_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:end], nil)
	}
	if err != nil {
		r.release()
		return err
	}
	increaseNonce(r.nonce)
	r.cached = length
	r.index = 0
	r.release()
	return nil
}

func (r *Reader) WriteTo(writer io.Writer) (n int64, err error) {
	if r.cached > 0 {
		writeN, writeErr := writer.Write(r.buffer[r.index : r.index+r.cached])
		if writeErr != nil {
			return int64(writeN), writeErr
		}
		n += int64(writeN)
		r.cached = 0
		r.release()
	}
	for {
		var length int
		length, err = r.readLength()
		if err != nil {
			return
		}
		err = r.readPayload(length)
		if err != nil {
			return
		}
		writeN, writeErr := writer.Write(r.buffer[:length])
		if writeErr != nil {
			return int64(writeN), writeErr
		}
		n += int64(writeN)
		r.cached = 0
		r.release()
	}
}

// readInternal skips empty chunks, so callers that index the buffer after it
// returns always have cached data to read.
func (r *Reader) readInternal() error {
	for {
		length, err := r.readLength()
		if err != nil {
			return err
		}
		err = r.readPayload(length)
		if err != nil {
			return err
		}
		if r.cached > 0 {
			return nil
		}
	}
}

func (r *Reader) ReadByte() (byte, error) {
	if r.cached == 0 {
		err := r.readInternal()
		if err != nil {
			return 0, err
		}
	}
	b := r.buffer[r.index]
	r.index++
	r.cached--
	r.release()
	return b, nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	if r.cached > 0 {
		n = copy(b, r.buffer[r.index:r.index+r.cached])
		r.cached -= n
		r.index += n
		r.release()
		return
	}
	length, err := r.readLength()
	if err != nil {
		return 0, err
	}
	end := length + Overhead

	if len(b) >= end {
		data := b[:end]
		_, err = io.ReadFull(r.upstream, data)
		if err != nil {
			return 0, err
		}
		_, err = r.cipher.Open(b[:0], r.nonce, data, nil)
		if err != nil {
			return 0, err
		}
		increaseNonce(r.nonce)
		return length, nil
	}
	err = r.readPayload(length)
	if err != nil {
		return 0, err
	}
	n = copy(b, r.buffer[:length])
	r.cached = length - n
	r.index = n
	r.release()
	return
}

func (r *Reader) Discard(n int) error {
	for {
		if r.cached >= n {
			r.cached -= n
			r.index += n
			r.release()
			return nil
		} else if r.cached > 0 {
			n -= r.cached
			r.cached = 0
			r.index = 0
		}
		err := r.readInternal()
		if err != nil {
			return err
		}
	}
}

func (r *Reader) Buffer() *buf.Buffer {
	r.acquire()
	buffer := buf.With(r.buffer)
	buffer.Resize(r.index, r.cached)
	return buffer
}

func (r *Reader) Cached() int {
	return r.cached
}

func (r *Reader) CachedSlice() []byte {
	if r.cached == 0 {
		return nil
	}
	return r.buffer[r.index : r.index+r.cached]
}

func (r *Reader) ReadWithLengthChunk(lengthChunk []byte) error {
	length, err := r.openLength(lengthChunk)
	if err != nil {
		return err
	}
	return r.readPayload(length)
}

func (r *Reader) ReadWithLength(length uint16) error {
	return r.readPayload(int(length))
}

func (r *Reader) ReadExternalChunk(chunk []byte) error {
	r.acquire()
	bb, err := r.cipher.Open(r.buffer[:0], r.nonce, chunk, nil)
	if err != nil {
		r.release()
		return err
	}
	increaseNonce(r.nonce)
	r.cached = len(bb)
	r.index = 0
	r.release()
	return nil
}

func (r *Reader) ReadChunk(buffer *buf.Buffer, chunk []byte) error {
	bb, err := r.cipher.Open(buffer.Index(buffer.Len()), r.nonce, chunk, nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	buffer.Extend(len(bb))
	return nil
}

// Writer holds its chunk buffer only for the duration of a write, unless
// Buffer or a BufferedWriter has staged data in it that is not yet flushed.
type Writer struct {
	upstream      io.Writer
	cipher        cipher.AEAD
	maxPacketSize int
	buffer        []byte
	size          int // 0 when the caller owns buffer
	pinned        bool
	nonce         []byte
	access        sync.Mutex
}

func NewWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int) *Writer {
	return &Writer{
		upstream:      upstream,
		cipher:        cipher,
		size:          maxPacketSize + PacketLengthBufferSize + Overhead*2,
		nonce:         make([]byte, cipher.NonceSize()),
		maxPacketSize: maxPacketSize,
	}
}

func NewRawWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int, buffer []byte, nonce []byte) *Writer {
	return &Writer{
		upstream:      upstream,
		cipher:        cipher,
		maxPacketSize: maxPacketSize,
		buffer:        buffer,
		nonce:         nonce,
	}
}

func (w *Writer) acquire() {
	if w.buffer == nil {
		w.buffer = getBuffer(w.size)
	}
}

func (w *Writer) release() {
	if w.size > 0 && w.buffer != nil && !w.pinned {
		putBuffer(w.buffer)
		w.buffer = nil
	}
}

func (w *Writer) Upstream() any {
	return w.upstream
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	w.acquire()
	defer w.release()
	for {
		offset := Overhead + PacketLengthBufferSize
		readN, readErr := r.Read(w.buffer[offset : offset+w.maxPacketSize])
		if readErr != nil {
			return 0, readErr
		}
		binary.BigEndian.PutUint16(w.buffer[:PacketLengthBufferSize], uint16(readN))
		w.cipher.Seal(w.buffer[:0], w.nonce, w.buffer[:PacketLengthBufferSize], nil)
		increaseNonce(w.nonce)
		packet := w.cipher.Seal(w.buffer[offset:offset], w.nonce, w.buffer[offset:offset+readN], nil)
		increaseNonce(w.nonce)
		_, err = w.upstream.Write(w.buffer[:offset+len(packet)])
		if err != nil {
			return
		}
		n += int64(readN)
	}
}

// The buffer goes back to a shared pool when a write ends, so writes hold
// access for their whole duration: a concurrent write must not still be
// using a buffer another connection has taken from the pool.
func (w *Writer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	w.access.Lock()
	defer w.access.Unlock()
	w.acquire()
	defer w.release()
	return w.write(p)
}

func (w *Writer) write(p []byte) (n int, err error) {
	for pLen := len(p); pLen > 0; {
		var data []byte
		if pLen > w.maxPacketSize {
			data = p[:w.maxPacketSize]
			p = p[w.maxPacketSize:]
			pLen -= w.maxPacketSize
		} else {
			data = p
			pLen = 0
		}
		binary.BigEndian.PutUint16(w.buffer[:PacketLengthBufferSize], uint16(len(data)))
		w.cipher.Seal(w.buffer[:0], w.nonce, w.buffer[:PacketLengthBufferSize], nil)
		increaseNonce(w.nonce)
		offset := Overhead + PacketLengthBufferSize
		packet := w.cipher.Seal(w.buffer[offset:offset], w.nonce, data, nil)
		increaseNonce(w.nonce)
		_, err = w.upstream.Write(w.buffer[:offset+len(packet)])
		if err != nil {
			return
		}
		n += len(data)
	}

	return
}

func (w *Writer) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	w.access.Lock()
	defer w.access.Unlock()
	w.acquire()
	defer w.release()
	var index int
	var err error
	for _, buffer := range buffers {
		pLen := buffer.Len()
		if pLen > w.maxPacketSize {
			if index > 0 {
				_, err = w.upstream.Write(w.buffer[:index])
				index = 0
				if err != nil {
					return err
				}
			}
			_, err = w.write(buffer.Bytes())
			if err != nil {
				return err
			}
		} else {
			if cap(w.buffer) < index+PacketLengthBufferSize+pLen+2*Overhead {
				_, err = w.upstream.Write(w.buffer[:index])
				index = 0
				if err != nil {
					return err
				}
			}
			binary.BigEndian.PutUint16(w.buffer[index:index+PacketLengthBufferSize], uint16(pLen))
			w.cipher.Seal(w.buffer[index:index], w.nonce, w.buffer[index:index+PacketLengthBufferSize], nil)
			increaseNonce(w.nonce)
			offset := index + Overhead + PacketLengthBufferSize
			w.cipher.Seal(w.buffer[offset:offset], w.nonce, buffer.Bytes(), nil)
			increaseNonce(w.nonce)
			index = offset + pLen + Overhead
		}
	}
	if index > 0 {
		_, err = w.upstream.Write(w.buffer[:index])
	}
	return err
}

// Buffer returns the writer's buffer for staging a header. The buffer stays
// held until a BufferedWriter flushes it.
func (w *Writer) Buffer() *buf.Buffer {
	w.acquire()
	w.pinned = true
	return buf.With(w.buffer)
}

func (w *Writer) WriteChunk(buffer *buf.Buffer, chunk []byte) {
	bb := w.cipher.Seal(buffer.Index(buffer.Len()), w.nonce, chunk, nil)
	buffer.Extend(len(bb))
	increaseNonce(w.nonce)
}

func (w *Writer) BufferedWriter(reversed int) *BufferedWriter {
	return &BufferedWriter{
		upstream: w,
		reversed: reversed,
	}
}

type BufferedWriter struct {
	upstream *Writer
	reversed int
	index    int
}

func (w *BufferedWriter) data() []byte {
	w.upstream.acquire()
	w.upstream.pinned = true
	return w.upstream.buffer[PacketLengthBufferSize+Overhead : len(w.upstream.buffer)-Overhead]
}

func (w *BufferedWriter) Write(p []byte) (n int, err error) {
	for {
		cachedN := copy(w.data()[w.reversed+w.index:], p[n:])
		w.index += cachedN
		if cachedN == len(p[n:]) {
			n += cachedN
			return
		}
		err = w.Flush()
		if err != nil {
			return
		}
		n += cachedN
	}
}

func (w *BufferedWriter) Flush() error {
	defer w.unpin()
	if w.index == 0 {
		if w.reversed > 0 {
			_, err := w.upstream.upstream.Write(w.upstream.buffer[:w.reversed])
			w.reversed = 0
			return err
		}
		return nil
	}
	buffer := w.upstream.buffer[w.reversed:]
	binary.BigEndian.PutUint16(buffer[:PacketLengthBufferSize], uint16(w.index))
	w.upstream.cipher.Seal(buffer[:0], w.upstream.nonce, buffer[:PacketLengthBufferSize], nil)
	increaseNonce(w.upstream.nonce)
	offset := Overhead + PacketLengthBufferSize
	packet := w.upstream.cipher.Seal(buffer[offset:offset], w.upstream.nonce, buffer[offset:offset+w.index], nil)
	increaseNonce(w.upstream.nonce)
	_, err := w.upstream.upstream.Write(w.upstream.buffer[:w.reversed+offset+len(packet)])
	w.reversed = 0
	w.index = 0
	return err
}

func (w *BufferedWriter) unpin() {
	w.upstream.pinned = false
	w.upstream.release()
}

func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
