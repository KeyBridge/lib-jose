# JOSE - JSON Object Signing and Encryption

JOSE is a framework intended to provide a method to securely transfer claims 
(such as authorization information) between parties. The JOSE framework provides 
a collection of specifications to serve this purpose.  

The standard provides a general approach to signing and encryption of any content, 
not necessarily in JSON. However, it is deliberately built on JSON and base64url 
to be easily usable in web applications. 
Also, while being used in OpenID Connect, it can be used as a building block in other protocols.

JOSE consists of several RFCs:

 * [7515 JWS](https://tools.ietf.org/html/rfc7515)    JSON Web Signature, describes producing and handling signed messages
 * [7516 JWE](https://tools.ietf.org/html/rfc7516)    JSON Web Encryption, describes producting and handling encrypted messages
 * [7517 JWK](https://tools.ietf.org/html/rfc7517)    JSON Web Key, describes format and handling of cryptographic keys in JOSE
 * [7518 JWA](https://tools.ietf.org/html/rfc7518)    JSON Web Algorithms, describes cryptographic algorithms used in JOSE
 * [7519 JWT](https://tools.ietf.org/html/rfc7519)    JSON Web Token, describes representation of claims encoded in JSON and protected by JWS or JWE

plus

 * [7797 JUP](https://tools.ietf.org/html/rfc7797)    JSON Web Signature for Unencoded Payloads

A number of examples are defined in: 
 
 * [7520 JOSE](https://tools.ietf.org/html/rfc7520)    Examples of Protecting Content Using JOSE

## Installation and key length errors

OpenJDK, Oracle JDK, and some non-US JDK distributions have JCE policy files that do not allow strong encryption. For these JDKs you must [install JCE policy files](docs/jce-installation.md) that support full length encryption keys.

## Implementation profile

This implementation includes a default profile with algorithms selected to run on all JVM instances. 

See the [Java Cryptography Architecture (JCA) Documentation](https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html) for more information about algorithm selection.


# Hello world JWT example

A JSON web token can be signed and/or encrypted, and a public / private key pair or
a shared secret may be used. Here we show the simplest case: signing a JWT claims
object with a shared secret.

```java
/**
 * Create a JWT claims object. The minimum configuration required the
 * issuer, audience and subject. Declare a duration if the token has a
 * time-to-live.
 */
 JwtClaims  claims = new JwtClaims()
   .withIssuer(senderKeyId)
   .withAudience(senderKeyId)
   .withSubject(recipientKeyId)
   .withDuration(Duration.ofDays(30));

/**
 * Create or retrieve the shared secret or the sender's key pair. If
 * available, a key id can help to find the key in a database or keystore.
 * When using a shared secret the key id is typically required.
 */
private static String sharedSecret;
private static String senderKeyId;

/**
 * Sign the JWT claims with the sender's private key. A shared secret could
 * alternatively be used. The result is a JSE compact-form encoded JSON
 * string. This is the JSON Web Token.
 */
String jsonWebToken = JwtUtility.sign(claims, sharedSecret, senderKeyId);
```


## More examples

See the following examples for useful sample code:

* [Key Bridge JOSE utilities](src/main/java/ch/keybridge/jose/readme.md)
* [JSON Web Token examples](src/main/java/org/ietf/jose/jwt/examples.md)
* [JSON Web Signature examples](src/main/java/org/ietf/jose/jws/examples.md)
* [JSON Web Encryption examples](src/main/java/org/ietf/jose/jwe/examples.md)
* [JoseFactory utility class examples](docs/examples.md)

All code used in these examples and other sample code are available in the unit test. See
`src/test/java/org/ietf/jose/` and 
`src/test/java/ch/keybridge/jose`.


## Brief summary introductions

* [JSON Web Signatures](docs/about-jws.md)
* [JSON Web Encryption](docs/about-jwe.md)
* [JSON Web Tokens](docs/about-jwt.md)
* [JSON Web Keys](docs/about-jwk.md)
* [JSON Web Algorithms](docs/about-jwa.md)

# License

Copyright 2018 Key Bridge. Published under the Apache 2.0 license.

# Other implementations

A few external resources for non-Java implementations, code quality comparison,
and interoperability testing.

 * [jwt.io](https://jwt.io/) - a catalog of open source JWT implementations
 * [jose4j](https://bitbucket.org/b_c/jose4j/overview) another complete implementation in Java
