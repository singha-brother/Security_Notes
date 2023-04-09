# Active Domain Enumeration

1. Submit the FQDN of the nameserver for the "inlanefreight.htb" domain as the answer.
```sh
$ dig ns inlanefreight.htb @$IP
```

2. Identify how many zones exist on the target nameserver. Submit the number of found zones as the answer.
6. Which IP address is assigned to the "us.inlanefreight.htb" subdomain. Submit the IP address as the answer.

```sh
$ dig axfr inlanefreight.htb @ns.inlanefreight.htb
```

3. Find and submit the contents of the TXT record as the answer.
- dns.txt -> DNS results from above 
```sh
cat dns.txt | while read i; do dig axfr $i @ns.inlanefreight.htb; echo $i; done
```

```sh
$ dig txt internal.inlanefreight.htb @$IP
```

4.  What is the FQDN of the IP address 10.10.34.136?
5. What FQDN is assigned to the IP address 10.10.1.5? Submit the FQDN as the answer.

```sh
$ dig axfr internal.inlanefreight.htb  @$IP
```

7. Submit the number of all "A" records from all zones as the answer.
- count from two zones