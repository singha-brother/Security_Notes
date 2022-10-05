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
