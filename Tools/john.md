# John-The-Ripper

```sh
john [options] [path to file]
john --wordlist=[path to wordlist] [path to file]
john --format=[format] --wordlist=[path to wordlist] [path to file]
john --list=formats | grep -iF "md5" # find supported formats and grep something wanted 
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```
- identify hashes by hash-id.py

- etc/shadow files
```sh
unshadow [path to passwd] [path to shadow] > unshadow.txt
```

## zip2john

```sh
zip2john [options] zip_file.zip > forjohn.txt 
john --wordlist=... forjohn.txt 
```

## rar2john

```sh
rar2john rarfile.rar > forjohn.txt
john --wordlist=.. forjohn.txt
```

## ssh2john

```sh
python ssh2john.py id_rsa > forjohn.txt
john --wordlist=.. forjohn.txt
```
