## What are WebSockets?

- bi-directional, full duplex communications protocol initiated over HTTP
- used in modern web applications for streaming data and other asynchronous traffic

### Difference between HTTP and WebSockets

- HTTP
  - client sends a request and the server returns a response
  - response occurs immediately and the transaction is complete
  - even if the network connection stays open, this will be used for a separate transaction of a request and response
- WebSockets
  - initiated over HTTP and are typically long-lived
  - messages can be sent in either direction at any time and are not transactional in nature
  - the connection will normally stay open and idel until either the client or the server is ready to send a message
  - useful in situations where low-latency or server-initiated messages are required, such as real time feeds of financial data

### How are WebSocket connections established?

```js
var ws = new WebSocket("wss://normal-site.com/chat");
```

- wss - encrypted TLS connection
- ws - unencrypted connection

- The browser issues a WebSocket handshake request like the following:

```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

- WebSocket handshake response like the following:

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

- The network connection remains open and can be used to send WebSocket messages in either direction

- `Connection`, `Upgrade` headers in the request and response indicate that this is a WebSocket handshake
- `Sec-WebSocket-Version` - WebSocket protocol version that the client wishes to use. (13 typically)
- `Sec-WebSocket-Key` - in request header contains Base64-encoded random value, randomly generated in each handshake request
- `Sec-WebSocket-Accept` response header - hash of the value submitted in the `Sec-WebSocket-Key` request header, concatenated with a specific string defined in the protocol specification

---

- Once a WebSocket connectoin has been established, messages can be sent asynchronously in either direction by the client or server

- Simple message could be sent from the browser using client-side JS like:
  `ws.send("Hello World!");`

- WebSocket messages can contain any content or data format.
- In modern applications, it is common for JSON to be used to send structured data within WebSocket messages.

eg - `{"user": "Peter", "content": "Hi There"}`

---

## WebSockets security vulnerabilities

- user-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as SQL injection or XXE
- some blind vulnerabilities reached via WebSockets might only be detectable using OAST techniques
- if attacker-controlled data is transmitted via WebSockets to other application users, then it may lead to XSS or other client-side vulnerabilities

### Manipulating WebSockets Message

- majority of input-based vulnerabilities affecting WebSockets can be found and exploited by tempering with the contents of WebSocket messages
- eg - chat message sent to server look looks like

```json
{ "message": "Hello!" }
```

- contents of the message are transmitted via WebSockets to another user, and rendered in the user's browser as

```html
<td>Hello!</td>
```

- in this situation, if there is no input processing or defenses, can perform XSS

```json
{ "message": "<img src=x onerror=alert(1)>" }
```

### Manipulating WebSockets Handshake

- misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header
