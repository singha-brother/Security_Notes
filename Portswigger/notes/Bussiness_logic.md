## Excessive trust in client-side control

### 1. [Doesn't adequately validate user input](!https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls)

eg - when buying an item, price calculation is only taken place at client side.

In POST request, change this
`productId=1&redir=PRODUCT&quantity=1&price=1334000` to
`productId=1&redir=PRODUCT&quantity=10&price=1`

### 2. [2FA broken logic](!https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

- In POST /login2, change `verify=carlos` and intruded the **mfa-code** from `0000 - 9999` and find the difference in GET request.

- Then, in GET /login2, change the `verify=carlos` and fill the code from above.

## Failing to handle uncoventional input

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
