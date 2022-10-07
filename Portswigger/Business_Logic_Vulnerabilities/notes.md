## What are Business Logic Vulnerabilities?

- flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior
- enables attackers to manipulate legitimate functionality to achieve a malicious goal
- not related to a business
- **application logic vulnerabilities**, **logic flaws**

- one of the main purposes of business logic is to enforce the rules and constraints that were defined when designing the application or functionality
- prevent users from doing things that will have a negative impact on the business or that simply don't make sense
- difficult to detect using automated vulnerability scanners
- logic flaws are a great target for bug bounty hunters and manual testers in general

## How do business logic vulnerabilities arise?

- design and development teams make flawed assumptions about how users will interact with the application, and lead to inadequate validation of user input
- common in overly complicated systems that even the development team themselves do not fully understand

## Impacts of business logic vulnerabilities

- broad category and highly variable
- unintended behavior can potentially lead to high-severity attacks if the attacker is able to manipulate the application in the right way
- depends on what functionality it is related to
- can potentially exploit this for privilege escalation, bypass authentication entirely , gaining access to sensitive data and functionality

## Some examples

- although individual instances of logic flaws differ hugely, they can share many common themes
- they can be loosely grouped based on the initial mistakes that introduced the vulnerability in the first place

### Excessive trust in client-side control

- fundamentally flawed assumption is that the users will only interact with the application via the provided web interface
- accepting data at face value, without performing proper integrity checks and server-side validation can allow an attacker to do all kinds of damage with relatively minimal effort

### Failing to handle unconventional input

- one aim of the application logic is to restrict user input to values that adhere to the business rules
- the application may be designed to accept arbitary values of a certain data type, but the logic determines whether or not this value is acceptable from the perspective of the business
- eg - numeric data type might accept negative values
  - fund transfer between two bank accounts

```php
$transferAmount = $_POST['amount'];
$currentBalance = $user->getBalance();

if ($transferAmount <= $currentBalance) {
    // complete the transfer
} else {
    // block : insufficient
}
```

- an attacker send -$1000 to the victim's account, this might result in receiving $1000 from the victim instead

- try submitting unconventional values
- try input in ranges that legitimate users are unlikely to ever enter
- eg - exceptionally high or low numeric inputs and abnormally long strings for text-based fields, or unexpected data types
- by observing the application's reponse, try and see
  - are there any limits that are imposed on the data?
  - what happens when you reach those limits?
  - is any transformation or normalization being performed on your input?

### 1. [High-level logic vulnerability](!https://portswigger.net/academy/labs/launch/8593e55b788d1c4403ccad45020972079a8e89c5669ecf6d9be2cd5c69c77877?referrer=%2fweb-security%2flogic-flaws%2fexamples%2flab-logic-flaws-high-level)

- change the amount of other items to minus (-) values and the price becomes minus (-).
- buy the item that you want.
- Note - the price must not be minus (-).

### 2. [Low-level logic flaw](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)

- if the price becomes above (2,147,483,647), it will change to negative value.

### 3. [Inconsistent handling of exceptional input](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)

- create email address of long name
- eg - `very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-long-email-name-very-lo@dontwannacry.com.exploit-0ab6004f03bb9950c000556f01ca00e9.web-security-academy.net`

- end with `.exploit-0ab6004f03bb9950c000556f01ca00e9.web-security-academy.net`, so that email enter the email box

- before that the email contains exactly 256 characters and the application truncate it exactly.

## Making flawed assumptions about user behavior

### 1. [Inconsistent security controls](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)

- first create user account with `anything@exploit-0ab6004f03bb9950c000556f01ca00e9.web-security-academy.net`

- then update the email with `anything@dontwannacry.com`

### 2. [Weak isolation on dual-use endpoint](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint)

- POST request for changing password `csrf=NFihVvPzqFnN58SzjL2FeAp2sPuJrDRz&username=weiner&current-password=peter&new-password-1=test&new-password-2=test`
- change it to `username=administrator` and remove `current-password`
- login as admin with password `test`

### 3. [Password reset broken logic](!https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)

- change the user name to `carlos` when reseting password.

### 4. [2FA simple bypass](!https://portswigger.net/academy/labs/launch/55a6f6d2de02362486d2c507f3191adb99fb573cd1583e7a69246d62445ed703?referrer=%2fweb-security%2fauthentication%2fmulti-factor%2flab-2fa-simple-bypass)

- login to your account. click the Email client and access your email
- go to account page `/your-account`
- logout
- login with victim credentials
- when prompted for the verification code, manually change the URL to `/your-account`.

### 5. [Insufficient workflow validation](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation)

- buy the product with low price and will get a `GET /cart/order-confirmation?order-confirmed=true HTTP/1.1` request in Burp.

- place the item with higher price in cart and then resend above the GET request.

### 6. [Authentication bypass via flawed state machine](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine)

- forward the POST request from login page then drop the GET request of role-selector

- then go back to `/admin` and default value is administrator.

## Domain-specific flaws

### 1. [Flawed enforcement of business rules](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules)

- Get 2 discount cupons and then fill them alternatively.

### 2. [Infinite money logic flaw](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money)
