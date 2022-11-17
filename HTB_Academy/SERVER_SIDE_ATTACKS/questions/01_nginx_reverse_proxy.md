- Replicate the steps shown in this section to connect to the above server's "hidden" Tomcat page through the AJP proxy, then write the Tomcat version as your answer. Remember that the port you will see next to "Target:" will be the AJP proxy port. Answer format: X.X.XX

- change the server ip and port from question from `/etc/nginx/conf/nginx.conf`

```json
http {
	...

    upstream tomcats {
	server <IP:PORT>;
	keepalive 10;
	}
    server {
        listen 8090;
        location / {
            ajp_keep_conn on;
            ajp_pass tomcats;
        }
    }
    ...
}
```

```sh
❯ curl http://127.0.0.1:8090
```
