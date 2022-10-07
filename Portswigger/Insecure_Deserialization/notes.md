## What is serialization?

- process of converting complex data structures, such as objects and their fields, into a 'flatter' format that canbe sent and received as a sequential stream of bytes
- serializing data makes it much simpler to:

  - write complex data to inter-process memory, a file, or a database
  - send complex data, for example, over a network, between different components of an application or in an API call

- when serializing an object, its state is also persisted; the object's attributes are preserved along with their assigned values

## Serialization vs Deserialization

- Deserialization - process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized

![deserialization_diagram](/Portswigger/images/deserialization-diagram.jpg)

- many programming languages offer native support fo serialization
- some languages serialize objects into binary formats whereas other uses differnet string format with varying degrees of human readability
- all of the original object's attributes are stored in the serialized data stream including any private fields
- to prevent a field from being serialized, it must be explicitly marked as "transient" in the class declaration

## What is insecure deserialization?

- Insecure deserialization is when user-controllable data is deserialized by a website
- enables an attacker to manipulate serialized objects in order to pass harmful data into the application code
- even possible to replace a serialize object with an object of an entirely different class (object injection)

## How do insecure deserialization aries?

- as there is a general lack of understanding of how dangerous deserializing user-controllable data can be
- user input should never be deserialized at all
- as deserialized objects are often assumed to be trustworthy
- due to the number of dependencies that exist in modern websites

## Impact of insecure deserialization

- very severe as it provides an entry point to a massively increased attack surface
- allows an attacker to reuse existing application code in harmful ways, resulting in numerous other vulnerabilities, often RCE
- other impacts - privilege escalation, arbitary file access and denial-of-service attacks

## How to exploit

### How to identify insecure deserialization

- during auditing, look at all data being passed into the website and try to identify anything that looks like serialized data

#### PHP serialization format

- eg - consider a User object with the attribures:

```php
$user->name = "carlos";
$user->isLoggedIn = true;
```

- When serialized, this object may look something like this:

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

> O:4:"User" - an object with the 4 character class name "User"  
> 2 - the object has 2 attributes  
> s:4:"name" - the key of the first attribute is the 4-character string "name"  
> s:6:"carlos" - the value of the first attribute is the 6-character string "carlos"  
> s:10:"isLoggedIn" - the key of the second attribute is the 10-character string "isLoggedIn"  
> b:1 - the value of the second attribute is the boolean value true

- native methods of PHP serialization are `serialize()` and `unserialize()`
- if you have source code access, find `unserialize()` anywhere in the code

#### JAVA serialization format

- JAVA use binary serialization formats
- more difficult ot read
- serialized Java objects always beign with the same bytes which are encoded as `ac ed` in hexadecimal and `rO0` in Base64
- any class that implements the interface `java.o.Serializable` can be serialized and deserialized
- if you have source code access, find `readObject()` method, which is used to read and deserialize data from an `InputStream`

### Manipulating serialized objects

- exploiting can be as easy as changing an attribute in a serialized object
- if object state is persisted, you can study the serialized data to identify and edit interesting attribute values
- then pass the malicious object into the website via its deserialization process
- this is the initial step for the basic deserialization exploit
- there are two approaches to manipulate serialized objects
  - edit object directly in its byte stream form
  - write a short script in the corresponding language to create and serialize the new object

### Modifying object attributes

- when tampering with the data, as long as the attacker preserves a valid serialized object, the deserialization process will create a server-side object with the modified attribute values
- eg - website that uses a serialized User object to store data about a user's session in a cookie and the attacker spotted this serialized object in an HTTP request, they might decode it to find the following byte stream:

```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```

- `isAdmin` is an obvious point of interest
- attacker could simply change the boolean value of the attribute to 1, re-encode the object, and overwrite their current cookie with this modified value

- let's say the website uses this cookie to check whether the current user has access to certain admin functionality

```php
$user = unserialize($_COOKIE);
if ($user->isAdmin === true) {
  // allow access to admin interface
}
```

### Modifying data types

- in PHP-based logic, it has loose comparison operator (==) when comparing data types
- `5 == "5"` -> `true`
- `5 == "5 of something"` will treated as `5 == 5`
- `0 == "example string"` -> `true`

eg - if this loose comparison operator is used in conjunction with user-controllable data from a deserialized object

```php
$login = unserialize($_COOKIE);
if ($login['password'] == $password) {
  // login successfully
}
```

- if an attacker modified the password attribute so that it contained an integer `0` instead of the expected string, it will login successfully.

- when modifying data types in any serialized object format, it is important to update any type labels and length indicators in the serialized data

### Using application funcitonality

- sometimes, website's functionality might also perform dangerous operations on data from a deserialized object
- then, can use insecure deserialization to pass in unexpected data and leverage the related functionality to do damage
- eg - part of website's Delete User functionality, the user's profile picture is deleted by accessing the file path in the `$user->image_location` attribute
  - if the `$user` was created from a serialized object, an attacker can exploit this by passing in a modified object with the `image_location` set to an arbitary file path

### Magic methods

- special subset of methods that you don't have to explicitly invoke; invoked automatically whenever a particular event or scenario occurs
- common features of OOP
- eg - in PHP `__construct()`, in Python `__init__`
- they can become dangerous when the code that they execute handles attacker-controlled data, eg - from a deserialized object
- some languages have magic methods that are invoked automatically during the deserialization process
- eg - PHP's `unserialize()` method looks for and invokes an object's `__wakeup()` magic method
  - in Java, `ObjectInputStream.readObject()` method, which is used to read data from the initial byte stream and essentially acts like a constructor for "reinitializing" a serialized object.

### Injecting arbitary objects

- deserialization methods do not typically check what they are deserializing and can pass in objects of any serializable class that is available to the website and the object will be deserialized

### Gadget chains

- gadget - snippet of code that exists in the application that can help an attacker to achieve a particular goal
- an individual gadget may not directly do anything harmful with user input
- but, the attacker's goal might simply be to invoke a method that will pass their input into another gadget
- by chaining multiple gadget together in this way, an attacker can potentially pass their input into a dangerous "sink gadget"
- gadget is not a payload; all of the code already exists on the website
- only thing the attacker controls is the data that is passed into the gadget chain

#### Working with pre-built gadget chains

- it is almost impossible without source code access
- there are several tools available that provide a range of pre-discovered chains that have been successfully exploited on other websites
- you can use these tools to both identify and exploit insecure deserialization with relatively little effort
- one such tool for Java deserialization is `ysoserial`
