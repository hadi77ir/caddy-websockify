# Websockify for Caddy
Easily integrate "websockify" into your [Caddy](https://github.com/caddyserver/caddy) setup with a single directive.

## What is Websockify?
It is very simple: Proxy TCP connections over WebSockets.

First implementations were used by noVNC project to bring native VNC from TCP to WebSockets. Later, WebSockets were used
to circumvent Great FireWall of China, as its traffic behind TLS was indistinguishable from innocent HTTPS traffic.

It can be used to serve streaming connections to target TCP/Unix sockets through CDNs (such as CloudFlare). Useful for
hiding your TCP endpoints behind CDNs and WAFs, adding another layer of security.

## How has it become possible?
Through [wsproxy](https://github.com/hadi77ir/wsproxy) and [Gorilla's Websocket](https://github.com/gorilla/websocket)
implementation. wsproxy implements a standalone websockify client and server, which can be used in conjunction with this
module as its client.

## What are the limitations?
Gorilla's Websocket implementation is limited to HTTP/1.1 and this is mostly because of how HTTP/2
has been implemented in Go standard library.

## How can I use it?
You need to build Caddy yourself and include this plugin in it. This is as easy as executing the following lines:
```shell
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/hadi77ir/caddy-websockify
```

Then either launch it directly:
```shell
./caddy websockify -listen ':80' 'tcp://127.0.0.1:1080'
```

or configure using a Caddyfile:
```shell
mywebsite.com {
  websockify /ssh-ws tcp://127.0.0.1:22
}
```
### A fully-fledged example
Your Caddyfile for a website with:
- 
- WordPress installation at `/var/www/wordpress/`
- PHP-FPM socket at `/run/php/php-version-fpm.sock`
- SSH at `127.0.0.1:22`
- VMess at `127.0.0.1:8080`
- MTProto at `127.0.0.1:9090`
- API server at `127.0.0.1:2080`

may look like this:
```
tls myemail@mail.local
example.com {
	root * /var/www/wordpress
	websockify /ssh-ws tcp://127.0.0.1:22
	websockify /vmess tcp://127.0.0.1:8080
	websockify /mtproto tcp://127.0.0.1:9090
	reverse_proxy /api/* 127.0.0.1:2080
	encode gzip
	php_fastcgi unix//run/php/php-version-fpm.sock
	file_server
}
```

For more information on configuration via Caddyfile, visit [official documentation](https://caddyserver.com/docs/caddyfile).
## License
Apache 2.0 License

```
   Copyright 2023 Mohammad Hadi Hosseinpour
   Copyright 2015 Matthew Holt and The Caddy Authors
   

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
