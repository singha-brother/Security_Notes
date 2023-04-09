# Basic Syntax

```python
def queueRequests(target, wordlists):
	engine = RequestEngine(
		endpoint=target.endpoint, # can write - https://www.example.com:443, etc
		concurrentConnections=5,
		requestsPerConnection=100,
		pipeline=False
		)
	for word in open('/path/to/wordlist'):
		engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
	if req.status != 404:
		table.add(req)
```

# QueueRequests

```python
engine = RequestEngine(
	endpoint=target.endpoint,
	concurrentConnections=100,
	requestsPerConnection=100,
	pipeline=True,
	maxRetriesPerRequest=0,
	engine=Engine.THREADED # BURP, BURP2, HTTP2 -> not working in my machine
	maxQueueSize=10,
	timeout=5,
	autoStart=False  
	)

# if autoStart = False, engine.start(timeout=5) need to be called
```

- multiple parameters

```python
for firstWord in open('/path/to/file1'):
	for secondWord in open('path/to/file2'):
		engine.queue(target.req, [firstWord.rstrip(), secondWord.rstrip()])
```

- arbitary requests

```python
oddRequest = """GET /static/style.css HTTP/1.1
Host: hackxor.net

"""
engine.queue(oddRequest)
```




---

# HandleResponse

- def handleResponse(req, interesting)

- eg
```
if "404 Not Found" not in req.response
if req.status != 404
req.wordcount
req.length
req.response
```

- save output

```python
if interesting:
	table.add(req)
	data = req.response.encode('utf8')
	header, _, body = data.partition('\r\n\r\n')
	output_file = open('path/to/save', 'a+')
	output_file.write(body, + '\n')
	output_file.close()
```

---

# Decorator for handleResponse

eg - 
```python
@MatchStatus(200, 204)
def handleResponse(req, interesting):
	table.add(req)
```
eg - 
- @FilterStatus(200, 204)
- @MatchSizeRange(100, 1000)
- @MatchRegex(r".*Set-Cookie.*")
- @MatchRegex(r".*SECRETCOOKIENAME.*")
- @FilterRegex(r".*Not Found.*")

```python
@MatchStatus(StatusCode,...)
@FilterStatus(StatusCode,...)
@MatchSize(RawSize,...)
@FilterSize(RawSize,...)
@MatchSizeRange(min,max)
@FilterSizeRange(min,max)
@MatchWordCount(WordCount,...)
@FilterWordCount(WordCount,...)
@MatchWordCountRange(min,max)
@FilterWordCountRange(min,max)
@MatchLineCount(LineCount,...)
@FilterLineCount(LineCount,...)
@MatchLineCountRange(min,max)
@FilterLineCountRange(min,max)
@MatchRegex(expression)
@FilterRegex(expression)
@UniqueSize(instances=1) # only allow through N instances of responses with a given status/size, 1 by default
@UniqueWordCount(instances=n)
@UniqueLineCount(instances=n)
```