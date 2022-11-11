# Skill Assessment - Broken Authentication

- 10 Nov, 2022

---

- Create new account
- password rules for registering the new users
	- the password must start with a capital letter
	- the password must contain at least one lowercase
	- the password must end with a digit
	- The password must contain at least one special char: $ # @
	- The password is not shorter than 20 characters

- Login page
	- too many login failures please wait 30 seconds before retry after 4 attempts

```
Set-Cookie: htb_sessid_persistent=b56ee839c1d3ea5978e14eb5fb12505533a35326; 
```
- persistent cookie not contain in profile.php
