# Easy Mode

```sh
nuclei -u https://my.target.site
nuclei -u my.target.site:8080
nuclei -l /path/to/list-of-targets.txt
subfinder -d targetdomain.com -slient | httpx | nuclei -t technologies/tech-detect.yaml
```

```sh
nuclei -u https://my.target.site -as #automatic web scan using wappalyzer technology detection to tags mapping
nuclei -u https://my.target.site -nt #only new templates
nuclei -u https://my.target.site -t template1.yaml -t template2.yaml -t folder/
nuclei -u https://my.target.site -tags sqli,xss
nuclei -u https://my.target.site -s critical,high,medium,low,info
nuclei -u https://my.target.site -rl 3 -c 2 # rate limiting 3 per second with 2 concurrent templates
nuclei -l list-of-targets.txt -timeout 1 # default 5 sec
nuclei -l list-of-targets.txt -retries 3
nuclei -l list-of-targets.txt -resume /path/to/resume.cfg # $HOME/.config/nuclei/resume-....cfg
```

```sh
nuclei -u https://my.target.site -H "Cookie:auth=something"
```

# Custom Templates

1. Template id
2. Template info
3. What data to send to the remote host
4. Instructions on how to analyze the response

eg -

```yaml
id: htpasswd

info:
  name: Detect exposed .htpasswd files
  author: geeknik
  severity: info
  tags: config,exposure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.htpasswd"
    matchers-conditions: and
    matchers:
      - type: word
        words:
          - ":{SHA}"
          - ":$apr1$"
          - ":$2y$"
        condition: or
      - type: status
        status:
          - 200
```

- allow HTTP Methods - GET, POST, PUT, etc
- also allow raw mode
- attack - batteringram, pitchfork, clusterbomb

## Fuzzing

```yaml
id: test-template

info:
    name: X Debug header fuzzing
    author: me
    severity: info
    description: Discover x-*-debug request headers

requests:
    - raw:
        - |
          GET / HTTP/1.1
          Host: {{Hostname}}
          X-{{fuzz}}-debug: 1

        redirects:true
        attack: batteringram
        payloads:
          fuzz: /path/to/wordlist
        # OR
          fuzz:
            - abc
            - def
            - admin
            - test
            - php
        stop-at-first-match: true
        matchers:
        - type: dsl
            dsl:
            - "len(body) > 109"
```

- DSL(domain specific language)
- eg 3

```yaml
id: x-php-debug

info:
  name: x-php-debug header info disclosure
  author: name
  severity: medium
  description: Detect x-php-debug request header information leak

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      x-php-debug: 1
    redirects: true
    max-redirects: 3

    matchers:
      - type: word
        words:
          - "Array"
          - "[HTTP_AUTHORIZATION]"
```

## Debug

```sh
nuclei -t template.yaml -validate
```

```sh
nuclei -l targets.txt -t template.yaml -v
nuclei -l targets.txt -t template.yaml -debug # show all requests and responses
nuclei -l targets.txt -t template.yaml -p http://127.0.0.1:8080 #proxy
```
