package websockify

import (
	"io"
	"net"

	"go.uber.org/zap"
)

func ConnCopy(dst, src net.Conn, logger *zap.Logger, copyDone chan struct{}) {
	defer func() {
		select {
		case <-copyDone:
			return
		default:
			close(copyDone)
		}
	}()
	_, err := io.Copy(dst, src)
	if err != nil {
		opErr, ok := err.(*net.OpError)
		switch {
		case ok && opErr.Op == "readfrom":
			return
		case ok && opErr.Op == "read":
			return
		default:
		}
		logger.Error("Failed to copy connection",
			zap.Error(err),
			zap.String("src", src.RemoteAddr().String()),
			zap.String("dst", dst.RemoteAddr().String()))
	}
}

func DuplexCopy(conn, rConn net.Conn, logger *zap.Logger) {
	ch := make(chan struct{})
	go ConnCopy(rConn, conn, logger, ch)
	go ConnCopy(conn, rConn, logger, ch)
	// rConn and conn will be closed by defer calls in handlers and proxyConn. There is nothing to do here.
	<-ch
}
