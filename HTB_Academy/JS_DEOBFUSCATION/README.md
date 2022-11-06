# Code Obfuscation

- technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view though performance may be slower
- usually achieved by using an obfuscation tool which takes code as an input and attempts to re-write the code in a way that is much more difficult to read depending on its design 

- since JS is usually used within browsers at the client-side and the code is sent to the user and executed in cleartext and so, obfuscation is very often used with JS
- Use cases - may be many reasons such as 
	- to hide the original code and its functions to prevent it from being reused or copied without the developer's permission
	- making it more difficult to reverse engineer the code's original functionality 
	- to provide a security layer when dealing with authentication or encryption to prevent attacks on vulnerabilities that may be found within the code 

## Basic Obfuscation

1. [minify JS code ](https://www.toptal.com/developers/javascript-minifier) and save as `.min.js`
2. [packing JS code](https://beautifytools.com/javascript-obfuscator.php)

- can execute this function at https://jsconsole.com 

## Advanced Obfuscation

- https://obfuscator.io/
- http://www.jsfuck.com/


# Deobfuscation

- Reverse the minify the code
	- Beautify in Browser Dev tools `{ }`
	- https://prettier.io/playground/
	- https://beautifier.io/

- Deobfuscate
	- http://www.jsnice.org/

# Decoding 

- base64
	- only contain alpha-numeric characters
	- most distinctive feature is padding using `=`
	- length of base64 encoded strings has to be in multiple of 4
	- resulting output is only 3 characters long and extra `=` is added as padding
	- `echo "Hello World!" | base64`
	- `echo SGVsbG8gV29ybGQhCg== | base64 -d`
- hex
	- encodes each character into its hex order in the ASCII table
	- eg - a is 61 in hex, b is 62 in hex,...
	- full ASCII table - `man ascii`
	- any string encoded in hex would be comprised of hex characters only `0-9, a-f`
	- hex encode - `xxd -p`
	- `❯ echo "Hello World!" | xxd -p`
	- `❯ echo 48656c6c6f20576f726c64210a | xxd -p -r`
- rot13
	- Ceaser cipher, most common is rot13 which shifts each character 13 times forward
	- `❯ echo "Hello World!" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
	- `❯ echo "Uryyb Jbeyq!" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

- tools 
	- https://www.boxentriq.com/code-breaking/cipher-identifier
	


# Commands

| **Command**   | **Description**   |
| --------------|-------------------|
| `curl http:/SERVER_IP:PORT/` | cURL GET request |
| `curl -s http:/SERVER_IP:PORT/ -X POST` | cURL POST request |
| `curl -s http:/SERVER_IP:PORT/ -X POST -d "param1=sample"` | cURL POST request with data |
| `echo hackthebox \| base64` | base64 encode |
| `echo ENCODED_B64 \| base64 -d` | base64 decode |
| `echo hackthebox \| xxd -p` | hex encode |
| `echo ENCODED_HEX \| xxd -p -r` | hex decode |
| `echo hackthebox \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | rot13 encode |
| `echo ENCODED_ROT13 \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | rot13 decode |

# Deobfuscation Websites

| **Website** |
| ----------------------------------|
| [JS Console](https://jsconsole.com) |
| [Prettier](https://prettier.io/playground/) |
| [Beautifier](https://beautifier.io/) |
| [JSNice](http://www.jsnice.org/) |

# Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `ctrl+u` | Show HTML source code in Firefox |