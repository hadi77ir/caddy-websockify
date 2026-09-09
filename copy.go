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
		case ok && opErr.Op == "writeto":
			return
		case ok && opErr.Op == "readfrom":
			return
		case ok && opErr.Op == "read":
			return
		default:
		}

		var srcAddr, dstAddr string
		if src != nil && src.RemoteAddr() != nil {
			srcAddr = src.RemoteAddr().String()
		}
		if dst != nil && dst.RemoteAddr() != nil {
			dstAddr = dst.RemoteAddr().String()
		}

		if logger != nil {
			logger.Error("Failed to copy connection",
				zap.String("src", srcAddr),
				zap.String("dst", dstAddr),
				zap.Error(err))
		}
	}
}

func DuplexCopy(conn, rConn net.Conn, logger *zap.Logger) {
	ch := make(chan struct{})
	go ConnCopy(rConn, conn, logger, ch)
	go ConnCopy(conn, rConn, logger, ch)
	// rConn and conn will be closed by defer calls in handlers and proxyConn. There is nothing to do here.
	<-ch
}
