- Target specifications

  - list `machine_IP google.com example.com`
  - range `10.11.12.15-20`
  - subnet `machine_IP/30`

- nmap -iL list_of_hosts.txt
- nmap -n (no DNS lookup)

| Scan Type         | Example                   |
| ----------------- | ------------------------- |
| ARP               | nmap -PR -sn IP           |
| ICMP Echo         | nmap -PE -sn IP           |
| ICMP Timestamp    | nmap -PP -sn IP           |
| ICMP address mask | nmap -PM -sn IP           |
| TCP SYN ping      | nmap -PS22,80 -sn IP      |
| TCP ACK ping      | nmap -PA22,80 -sn IP      |
| UDP Ping          | nmap -PU53,161,162 -sn IP |

| Option | Purpose             |
| ------ | ------------------- |
| -n     | no DNS lookup       |
| -R     | Reverse DNS lookup  |
| -sn    | host discovery only |
