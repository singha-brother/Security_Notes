## What is web cache poisoning?

- advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users
- involves two phases:
  1. attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload
  2. need to make sure that their response is cached and subsequently served to the intended victims

## How does a web cache work?

![Web cache](/Portswigger/images/caching.svg)

- if a server had to send a new response to every single HTTP request separately, this would likely overload the server, resulting in latency issues and a poor user experience
- caching is primarily a means of reducing such issues
- chche sits between the server and the user, saves (caches) the responses to particular requests, for a fixed amount of time
- if another user sends an equivalent request, the cache simply serves a copy of the cached response directly to the user, without any interaction from the back-end

## Cache keys

- when the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly or whether it has to forward the request for handling by the back-end server
- caches identify equivalent requests by comparing a predefined subset of the request's components (cache key)
- contain the request line and Host header
- components of the request that are not included in the cache key are said to be "unkeyed"
- if cache key of an incoming request matches the key of a previous request, the cache considers them to be equivalent
- serve a copy of the cached response that was generated for the original request
- applied to all subsequent requests with the matching cache key until the cached response expires
- other components of the request are ignored by the cache

## Impact of a web cache poisoning attack

- depends on

1. What exactly the attacker can successfully get cached?
2. Amount of traffic on the affected page

## Constructing a web cache poisoning attack

1. Identify and evaluate unkeyed inputs
