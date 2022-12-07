## Lab - 1: Manipulating WebSocket messages to exploit vulnerabilities (A)

- This online shop has a live chat feature implemented using WebSockets. Chat messages that you submit are viewed by a support agent in real time. To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

- use Burp Repeter, and send to server

```json
{ "message": "<img src=x onerror='alert(1)'/>" }
```

---

## Lab - 2: Manipulating the WebSocket handshake to exploit vulnerabilities (P)

- This online shop has a live chat feature implemented using WebSockets.It has an aggressive but flawed XSS filter.To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

- try with payload `<img src=1 onerror=alert(1)>` and chat was disconnect
- try to reconnect but cannot connect
- add `X-Forwarded-For` header with new IP address and can connect
- solution payload

```
<img src=1 oNeRrOr=alert`1`>
```

---
