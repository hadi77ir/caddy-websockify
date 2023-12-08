// Copyright 2023 Mohammad Hadi Hosseinpour
// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package websockify

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
	N "github.com/hadi77ir/wsproxy/pkg/net"
	C "github.com/hadi77ir/wsproxy/pkg/wsconn"
)

func init() {
	caddy.RegisterModule(new(ProxyHandler))
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "websockify",
		Usage: `[--listen <addr>] [--access-log] [--debug] [--header "Field: value"] <upstream> [<upstream>]`,
		Short: "Simple Websockify Solution",
		Long: `
Spins up a quick-and-clean Websockify server.

With no options specified, this command listens on a random available port
and proxies connection to one of given upstreams. The listen address can
be customized with the --listen flag and will always be printed to stdout.
If the listen address includes a port range, multiple servers will be started.

Upstreams should be in URL format like the following examples:
    
    tcp://127.0.0.1:1080/
    unix:///run/domain.sock

Access/request logging and more verbose debug logging can also be enabled.

Response headers may be added using the --header flag for each header field.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("listen", "l", ":0", "The address to which to bind the listener")
			cmd.Flags().BoolP("access-log", "", false, "Enable the access log")
			cmd.Flags().BoolP("debug", "v", false, "Enable more verbose debug-level logging")
			cmd.Flags().StringSliceP("header", "H", []string{}, "Set a header on the response (format: \"Field: value\")")
			// at least one upstream
			cmd.Args = cobra.MinimumNArgs(1)
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdWebsockify)
		},
	})
}

// ProxyHandler implements a simple responder for Websocket requests which
// bidirectionally copies the stream between both parties.
type ProxyHandler struct {
	// Counter increments each time a server is going to be dialed.
	// When reaches near its maximum, it will be set to zero.
	counter  atomic.Int64
	mutex    sync.RWMutex
	once     sync.Once
	upgrader *websocket.Upgrader
	dialers  []N.PrimedDialerFunc
	logger   *zap.Logger
	// Header fields to set on the response; overwrites any existing
	// header fields of the same names after normalization.
	Headers http.Header `json:"headers,omitempty"`

	// Upstream addresses to establish connections. Supports TCP and Unix
	// domain sockets. Must contain at least one element.
	// Examples: "127.0.0.1:1080", "unix:/run/server.sock"
	Upstream []string `json:"upstream,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*ProxyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.websockify",
		New: func() caddy.Module { return new(ProxyHandler) },
	}
}

// Provision sets up ProxyHandler.
func (s *ProxyHandler) Provision(ctx caddy.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.logger = ctx.Logger()
	s.upgrader = &websocket.Upgrader{
		Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
			// WORKAROUND: workaround for passing both status code and reason
			if setter, ok := r.Context().Value(ErrorSetterCtxKey).(ErrorSetterFunc); ok && setter != nil {
				setter(status, reason)
			}
		},
		CheckOrigin: func(r *http.Request) bool {
			// TODO: add origin validation functionality
			return true
		},
	}

	s.dialers = make([]N.PrimedDialerFunc, 0)
	for _, upstream := range s.Upstream {
		if err := s.addDialer(upstream); err != nil {
			return err
		}
	}
	return nil
}

const ErrorSetterCtxKey = "handler_error_setter_ws"

type ErrorSetterFunc func(status int, err error)

func (s *ProxyHandler) addDialer(addr string) error {
	if len(addr) == 0 {
		// empty not allowed
		return fmt.Errorf("empty upstream address")
	}
	dialer, err := N.CreateDialer(addr, nil)
	if err != nil {
		return fmt.Errorf("cannot construct a dialer: %s", err)
	}
	s.dialers = append(s.dialers, dialer)
	return nil
}

func (s *ProxyHandler) nextDialer() N.PrimedDialerFunc {
	ctr := s.counter.Add(1) - 1 // start at 0
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.dialers[ctr%int64(len(s.Upstream))]
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	websockify [<matcher>] <upstream> [<upstream>]
func (s *ProxyHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	s.Upstream = make([]string, 0)
	for d.NextArg() {
		arg := d.Val()
		s.Upstream = append(s.Upstream, arg)
	}
	return nil
}

func (s *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// set all headers
	for field, vals := range s.Headers {
		field = textproto.CanonicalMIMEHeaderKey(repl.ReplaceAll(field, ""))
		newVals := make([]string, len(vals))
		for i := range vals {
			newVals[i] = repl.ReplaceAll(vals[i], "")
		}
		w.Header()[field] = newVals
	}

	// do not allow Go to sniff the content-type, for safety
	w.Header()["Content-Type"] = nil

	// get the status code; if this handler exists in an error route,
	// use the recommended status code as the default; otherwise 200
	statusCode := http.StatusOK
	if reqErr, ok := r.Context().Value(caddyhttp.ErrorCtxKey).(error); ok {
		if handlerErr, ok := reqErr.(caddyhttp.HandlerError); ok {
			if handlerErr.StatusCode > 0 {
				statusCode = handlerErr.StatusCode
			}
		}
	}

	// upgrade to websocket
	var err error
	// WORKAROUND: workaround for passing both status code and reason
	r = r.WithContext(context.WithValue(r.Context(), ErrorSetterCtxKey, func(s int, e error) {
		statusCode = s
		err = e
	}))
	upgraded, _ := s.upgrader.Upgrade(w, r, w.Header())
	if upgraded == nil || err != nil {
		return caddyhttp.Error(statusCode, err)
	}
	defer func() {
		_ = upgraded.Close()
	}()

	// round-robin
	dialer := s.nextDialer()

	// dial target
	rConn, err := dialer()
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	defer func() {
		_ = rConn.Close()
	}()

	// construct a conventional net.Conn
	conn := C.WrapConn(upgraded)

	// bidirectional copy
	DuplexCopy(rConn, conn, caddy.Log())

	return nil
}

// cmdWebsockify is the command-line handler for running a server
// with this single directive
func cmdWebsockify(fl caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	// get flag values
	listen := fl.String("listen")
	accessLog := fl.Bool("access-log")
	debug := fl.Bool("debug")

	if fl.NArg() == 0 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("upstream not specified")
	}

	upstreams := fl.Args()

	// build headers map
	headers, err := fl.GetStringSlice("header")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid header flag: %v", err)
	}
	hdr := make(http.Header)
	for i, h := range headers {
		key, val, found := strings.Cut(h, ":")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !found || key == "" || val == "" {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("header %d: invalid format \"%s\" (expecting \"Field: value\")", i, h)
		}
		hdr.Set(key, val)
	}

	// expand listen address, if more than one port
	listenAddr, err := caddy.ParseNetworkAddress(listen)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	listenAddrs := make([]string, 0, listenAddr.PortRangeSize())
	for offset := uint(0); offset < listenAddr.PortRangeSize(); offset++ {
		listenAddrs = append(listenAddrs, listenAddr.JoinHostPort(offset))
	}

	// build each HTTP server
	httpApp := caddyhttp.App{Servers: make(map[string]*caddyhttp.Server)}

	for i, addr := range listenAddrs {
		var handlers []json.RawMessage

		// create route with handler
		handler := &ProxyHandler{
			Headers: hdr,
		}
		for _, upstream := range upstreams {
			handler.Upstream = append(handler.Upstream, upstream)
		}

		handlers = append(handlers, caddyconfig.JSONModuleObject(handler, "handler", "websockify", nil))
		route := caddyhttp.Route{HandlersRaw: handlers}

		server := &caddyhttp.Server{
			Listen:            []string{addr},
			ReadHeaderTimeout: caddy.Duration(10 * time.Second),
			IdleTimeout:       caddy.Duration(30 * time.Second),
			MaxHeaderBytes:    1024 * 10,
			Routes:            caddyhttp.RouteList{route},
			AutoHTTPS:         &caddyhttp.AutoHTTPSConfig{DisableRedir: true},
		}
		if accessLog {
			server.Logs = new(caddyhttp.ServerLogConfig)
		}

		// save server
		httpApp.Servers[fmt.Sprintf("websock%d", i)] = server
	}

	// finish building the config
	var false bool
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &false,
			},
		},
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(httpApp, nil),
		},
	}
	if debug {
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()}},
			},
		}
	}

	// run it!
	err = caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// to print listener addresses, get the active HTTP app
	loadedHTTPApp, err := caddy.ActiveContext().App("http")
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// print each listener address
	for _, srv := range loadedHTTPApp.(*caddyhttp.App).Servers {
		for _, ln := range srv.Listeners() {
			fmt.Printf("Server address: %s\n", ln.Addr())
		}
	}

	select {}
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*ProxyHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ProxyHandler)(nil)
)
