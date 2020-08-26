# Jose utility classes

**JSON Object Signing and Encryption**

Utility classes to simplify the integration and use of JOSE in your application.

 * [7515 JWS](https://tools.ietf.org/html/rfc7515)    JSON Web Signature, describes producing and handling signed messages
 * [7516 JWE](https://tools.ietf.org/html/rfc7516)    JSON Web Encryption, describes producting and handling encrypted messages
 * [7519 JWT](https://tools.ietf.org/html/rfc7519)    JSON Web Token, describes representation of claims encoded in JSON and protected by JWS or JWE

**JweUtility - encrypt and decrypt Java objects**

The JWE utility class provides methods for easy object encryption (write)
and decryption (read). Objects may be encrypted using the recipient's public key 
or a shared secret. 
The object must be readily serializable to / from JSON using the JSON-B. 
JSON-B is a standard binding layer for converting Java objects to/from JSON messages

Example: encrypt and decrypt an object using a public / private key pair

```java 
JsonObject object = ... // the object to encrypt
KeyPair recipientKeyPair = ... // the recipient key
String recipientKeyId = ... // the recipient key id (optional, set to null if not known)

// encrypt the object to an encoded string
String jsonCompact = JweUtility.encrypt(object, recipientKeyPair.getPublic(), recipientKeyId);

// jsonCompact is a JWE compact form encoded JSON string
// decrypt the encoded string to an object
JsonObject decrypted = JweUtility.decrypt(jsonCompact, JsonObject.class, recipientKeyPair.getPrivate());
```



**JwsUtility - sign and verify Java objects**

The JWS utility provides methods for easy object signing (write) and validation (read).
Objects may be signed using the senders private key or a shared secret. 
The object must be readily serializable to / from JSON using the JSON-B. 
JSON-B is a standard binding layer for converting Java objects to/from JSON messages

Example: sign and verify an object using a private / public key pair

```java
JsonObject object = ... // the object to encrypt
KeyPair senderKeyPair = ... // the sender key
String senderKeyId = ... // the sender key id (optional, set to null if not known)

// jsonCompact is a JSE compact form encoded JSON string
String jsonCompact = JwsUtility.sign(object, senderKeyPair.getPrivate(), senderKeyId);

// parse and verify the JSE compact form encoded JSON string
JsonObject verified = JwsUtility.verify(jsonCompact, JsonObject.class, senderKeyPair.getPublic());
```



**JwtUtility - write and read JSON web tokens**

The JWT utility provides methods for easy token creation (write) and parsing (read).
Tokens may be signed and/or encrypted. Signed tokens may be verified. Encrypted 
tokens may be decrypted.

Example: sign and encrypt, then descrypt and verify a JWT claims object

```java
KeyPair senderKeyPair;
KeyPair recipientKeyPair;
String senderKeyId;
String recipientKeyId;

// jsonCompact is a JWE compact form encoded JSON string
String jsonCompact = JwtUtility.signAndEncrypt(claims, senderKeyPair.getPrivate(), recipientKeyPair.getPublic(), senderKeyId, recipientKeyId);

// decrypt the encoded string to an object
// verify the sender signature
JwtClaims recovered = JwtUtility.decryptAndVerifySignature(jsonCompact, recipientKeyPair.getPrivate(), senderKeyPair.getPublic());
```


References

  * [Jakarta JSON Binding (JSON-B)](http://json-b.net/)
  * [Eclipse Yasson](https://eclipse-ee4j.github.io/yasson/)
  