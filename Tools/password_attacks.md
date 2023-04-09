## Hydra

```sh
hydra -l username -P wordlist.txt server service
hydra -l john -P /usr/share/wordlists/rockyou.txt $IP ftp
hydra -l john -P /usr/share/wordlists/rockyou.txt $IP ssh
```

- optional flags
  - -s PORT - to specify a non-default port
  - -v or -vV - for verbose
  - -t 16 - parallel connections to target (16 threads)
  - -d - debugging
