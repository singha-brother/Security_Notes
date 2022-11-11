# Authentication Credentials Handling

- how an applicaiton operates on passwords (password resets, password recovery or password change)
- password reset may be easy but loud way to bypass authentication
- users who forget their password can get a new one in three ways when no external authentication factor is used
1. By requesting a new one that will be sent via email by the application
2. By requesting a URL that will allow them to set a new one
3. By answer prefilled questions as proof of identity and then setting a new one

- always look for logic flaws in "forgot password" and "password change" funcationalities

# Guessable Answers

- often web applications authenticate users who lost their password by requesting that they answer one or multiple questions which the user filled during the registration phase and mostly hardcoded and cannot be chosen by them
- assuming we found such functionality on a target website, we should try to abuse it to bypass authentication
- questions like `What is your mother's maiden name? Which city were you born in?`
- those questions can be found by using `OSINT` or via brute-force attack
- when we find an app that keeps rotating questions, we should collect them to identify the easiest to brute force and mount the attack

- check **predictable_questions.py/php**

# Username injection

- when a user inputs the expected value, the reset functionality lets the user change the password or pass the authentication phase
- suppose we tested the reset password page, which contains input fields of password and confirm password (new password)
- try to inject a different username and/or email address, looking for a possible hidden input value or guessing any valid input name
- example of vulnerable code
```php
<?php
	if isset($_REQUEST['userid']) {
		$userid = $_REQUEST['userid'];
	} else if isset($_SESSION['userid']) {
		$userid = $_SESSION['userid'];
	} else {
		die("unknown userid");
	}
```
- like a web app that allows admins or helpdesk employees to reset other user's passwords
- often, the function that changes the password is reused and shares the same codebase with the one used by standard users to change their password
- an application should always check authorization before any change
- check if the user has the rights to modify the password for the target user

### Methods to attack

- with this in mind, we should enumerate the web app to identify how it expects the username or email field during the login phase when there are messages, or a communication exchange, or when we see other users' profiles
- collect a list of all possible input filed names, we will attack the application
- the attack will be executed by sending a password reset request while logged in with our user and injecting the target user's email or username through the possible field names (one at a time)

- eg - suppose the POST req to reset password looks like this
```
POST /username_injection.php HTTP/1.1
...
Content-Type: application/x-www-form-urlencoded

oldpasswd=P@ssword1&newpasswd=newPwd&confirm=newpasswd&submit=submit
```
- this will return a page like 
```html
<h2>Welcome htbuser, you have changed your password</h2>
```

- If you tamper with the request by adding the userid field, and can change the password of other users
```
POST /username_injection.php HTTP/1.1
...
Content-Type: application/x-www-form-urlencoded

oldpasswd=P@ssword1&newpasswd=newPwd&confirm=newpasswd&userid=htbadmin&submit=submit
```

