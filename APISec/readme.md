```bash
amass enum -list
amass enum -active -d crapi.apisec.ai
amass enum -active -d microsoft.com

mitmweb
## manual walkthrough the web and save as flows file
mitmproxy2swagger -i flows -o spec.yml -p http://crapi.apisec.ai -f flow

## in spec.yml file -> delete the ignore: in front of api path
mitmproxy2swagger -i flows -o spec.yml -p http://crapi.apisec.ai -f flow --examples

wfuzz -z file,/path/to/wordlist -H "Header:here" -H "MoreHeader":here" -d "{\"your-json\":FUZZ}" --sc 200 -p http://localhost:8080 http://example.com
```
