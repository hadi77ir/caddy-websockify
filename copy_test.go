package websockify

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	reader io.Reader
	writer io.Writer
	closed bool
	mu     sync.Mutex
}

func newMockConn(reader io.Reader, writer io.Writer) *mockConn {
	return &mockConn{
		reader: reader,
		writer: writer,
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.reader == nil {
		return 0, io.EOF
	}
	return m.reader.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writer == nil {
		return 0, io.ErrClosedPipe
	}
	return m.writer.Write(b)
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConnCopy(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("successful copy", func(t *testing.T) {
		testData := []byte("Hello, WebSocket!")
		src := newMockConn(bytes.NewReader(testData), nil)
		dstBuf := &bytes.Buffer{}
		dst := newMockConn(nil, dstBuf)

		copyDone := make(chan struct{})
		go ConnCopy(dst, src, logger, copyDone)

		select {
		case <-copyDone:
			// Success
		case <-time.After(1 * time.Second):
			t.Fatal("ConnCopy timed out")
		}

		if !bytes.Equal(dstBuf.Bytes(), testData) {
			t.Errorf("Expected %q, got %q", testData, dstBuf.Bytes())
		}
	})

	t.Run("copy with EOF", func(t *testing.T) {
		src := newMockConn(bytes.NewReader([]byte{}), nil)
		dst := newMockConn(nil, &bytes.Buffer{})

		copyDone := make(chan struct{})
		go ConnCopy(dst, src, logger, copyDone)

		select {
		case <-copyDone:
			// Success - EOF should close gracefully
		case <-time.After(1 * time.Second):
			t.Fatal("ConnCopy timed out")
		}
	})

	t.Run("multiple calls to close channel", func(t *testing.T) {
		testData := []byte("test")
		src := newMockConn(bytes.NewReader(testData), nil)
		dst := newMockConn(nil, &bytes.Buffer{})

		copyDone := make(chan struct{})
		go ConnCopy(dst, src, logger, copyDone)

		select {
		case <-copyDone:
			// First close
		case <-time.After(1 * time.Second):
			t.Fatal("ConnCopy timed out")
		}

		// Try to use the same channel again - should not panic
		src2 := newMockConn(bytes.NewReader(testData), nil)
		dst2 := newMockConn(nil, &bytes.Buffer{})

		// Simulate channel already closed
		go ConnCopy(dst2, src2, logger, copyDone)

		// Should handle already-closed channel gracefully
		time.Sleep(100 * time.Millisecond)
	})
}

func TestDuplexCopy(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("bidirectional copy", func(t *testing.T) {
		// Create two pairs of pipes for bidirectional communication
		clientReader, serverWriter := io.Pipe()
		serverReader, clientWriter := io.Pipe()

		clientConn := newMockConn(clientReader, clientWriter)
		serverConn := newMockConn(serverReader, serverWriter)

		// Start bidirectional copy in a goroutine
		done := make(chan struct{})
		go func() {
			DuplexCopy(clientConn, serverConn, logger)
			close(done)
		}()

		// Write from client side
		testData := []byte("client to server")
		go func() {
			clientWriter.Write(testData)
			clientWriter.Close()
		}()

		// Read on server side
		buf := make([]byte, len(testData))
		n, err := serverReader.Read(buf)
		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}
		if !bytes.Equal(buf[:n], testData) {
			t.Errorf("Expected %q, got %q", testData, buf[:n])
		}

		// Close pipes to trigger copy completion
		serverReader.Close()
		serverWriter.Close()
		clientReader.Close()

		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("DuplexCopy timed out")
		}
	})
}

func BenchmarkConnCopy(b *testing.B) {
	logger := zap.NewNop()
	testData := bytes.Repeat([]byte("benchmark test data"), 1024) // ~19KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := newMockConn(bytes.NewReader(testData), nil)
		dst := newMockConn(nil, io.Discard)

		copyDone := make(chan struct{})
		go ConnCopy(dst, src, logger, copyDone)
		<-copyDone
	}
}
