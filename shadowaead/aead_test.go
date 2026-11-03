package shadowaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"math/rand"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func newTestAEAD(t testing.TB) cipher.AEAD {
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// Chunks written by every Writer path decode to the same bytes through every
// Reader path, for both chunk sizes in use (classic and 2022).
func TestRoundTrip(t *testing.T) {
	for _, maxPacketSize := range []int{MaxPacketSize, 65535} {
		rng := rand.New(rand.NewSource(int64(maxPacketSize)))
		var wire bytes.Buffer
		writer := NewWriter(&wire, newTestAEAD(t), maxPacketSize)
		var want []byte

		header := writer.Buffer()
		header.Write([]byte("salt"))
		first := randomBytes(rng, 100)
		writer.WriteChunk(header, first)
		if err := writer.BufferedWriter(header.Len()).Flush(); err != nil {
			t.Fatal(err)
		}
		if writer.buffer != nil {
			t.Fatal("writer holds its buffer after the header flush")
		}
		wire.Next(4)

		for _, size := range []int{1, 17, 1000, maxPacketSize, maxPacketSize + 1, 3*maxPacketSize + 5} {
			p := randomBytes(rng, size)
			if _, err := writer.Write(p); err != nil {
				t.Fatal(err)
			}
			want = append(want, p...)
		}
		var vec []*buf.Buffer
		for _, size := range []int{5, 2000, maxPacketSize + 3, 40} {
			p := randomBytes(rng, size)
			vec = append(vec, buf.As(append([]byte(nil), p...)))
			want = append(want, p...)
		}
		if err := writer.WriteVectorised(vec); err != nil {
			t.Fatal(err)
		}
		if writer.buffer != nil {
			t.Fatal("writer holds its buffer between writes")
		}

		firstChunk := wire.Bytes()[:len(first)+Overhead]
		rest := wire.Bytes()[len(first)+Overhead:]
		readers := map[string]func(*Reader) ([]byte, error){
			"Read small": func(r *Reader) ([]byte, error) { return readAllWith(r, 7) },
			"Read large": func(r *Reader) ([]byte, error) { return readAllWith(r, 2*maxPacketSize) },
			"ReadByte": func(r *Reader) ([]byte, error) {
				var out []byte
				for {
					b, err := r.ReadByte()
					if err == io.EOF {
						return out, nil
					}
					if err != nil {
						return out, err
					}
					out = append(out, b)
				}
			},
			"WriteTo": func(r *Reader) ([]byte, error) {
				var out bytes.Buffer
				_, err := r.WriteTo(&out)
				if err == io.EOF {
					err = nil
				}
				return out.Bytes(), err
			},
		}
		for name, read := range readers {
			reader := NewReader(bytes.NewReader(rest), newTestAEAD(t), maxPacketSize)
			if err := reader.ReadExternalChunk(firstChunk); err != nil {
				t.Fatal(err)
			}
			got, err := read(reader)
			if err != nil {
				t.Fatalf("%d %s: %v", maxPacketSize, name, err)
			}
			if !bytes.Equal(got, append(append([]byte(nil), first...), want...)) {
				t.Fatalf("%d %s: got %d bytes, want %d", maxPacketSize, name, len(got), len(first)+len(want))
			}
			if reader.buffer != nil {
				t.Fatalf("%d %s: reader holds its buffer with nothing cached", maxPacketSize, name)
			}
		}
	}
}

func readAllWith(r *Reader, size int) ([]byte, error) {
	var out []byte
	p := make([]byte, size)
	for {
		n, err := r.Read(p)
		out = append(out, p[:n]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func TestReaderHoldsBufferOnlyWhileCached(t *testing.T) {
	var wire bytes.Buffer
	writer := NewWriter(&wire, newTestAEAD(t), 65535)
	if _, err := writer.Write(bytes.Repeat([]byte{'x'}, 100)); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(&wire, newTestAEAD(t), 65535)
	if reader.buffer != nil {
		t.Fatal("new reader holds a buffer")
	}
	p := make([]byte, 10)
	if _, err := reader.Read(p); err != nil {
		t.Fatal(err)
	}
	if reader.buffer == nil || reader.Cached() != 90 {
		t.Fatalf("want 90 cached bytes in a held buffer, got %d", reader.Cached())
	}
	if err := reader.Discard(90); err != nil {
		t.Fatal(err)
	}
	if reader.buffer != nil {
		t.Fatal("reader holds its buffer after the cache drained")
	}
}

func TestDiscardAcrossChunks(t *testing.T) {
	var wire bytes.Buffer
	writer := NewWriter(&wire, newTestAEAD(t), MaxPacketSize)
	writer.Write([]byte("abc"))
	writer.Write([]byte("defgh"))
	reader := NewReader(&wire, newTestAEAD(t), MaxPacketSize)
	if err := reader.Discard(5); err != nil {
		t.Fatal(err)
	}
	b, err := reader.ReadByte()
	if err != nil || b != 'f' {
		t.Fatalf("got %q, %v", b, err)
	}
}

func BenchmarkConnectionSetup(b *testing.B) {
	b.ReportAllocs()
	aead := newTestAEAD(b)
	p := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		var wire bytes.Buffer
		writer := NewWriter(&wire, aead, 65535)
		writer.Write([]byte("hello"))
		reader := NewReader(&wire, aead, 65535)
		reader.Read(p)
	}
}
