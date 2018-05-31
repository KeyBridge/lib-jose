# JOSE - JSON Object Signing and Encryption

JOSE is a framework intended to provide a method to securely transfer claims (such as authorization information) between parties. The JOSE framework provides a collection of specifications to serve this purpose.  

The standard provides a general approach to signing and encryption of any content, not necessarily in JSON. However, it is deliberately built on JSON and base64url to be easily usable in web applications. Also, while being used in OpenID Connect, it can be used as a building block in other protocols.

It consists of several RFCs:

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


# Hello World JWE example

**Clear text input**

```java
String sampleText = "sample text to sign and encrypt";
String signedAndEcryptedText = JOSE.write(sampleText, senderPrivateKey, recipientPublicKey, "myKeyId");
```

**Encryption and signing**

```json
{"protected":{"alg":"RSA1_5","kid":"myKeyId","enc":"A128CBC-HS256"},"encrypted_key":"jgz9i1TlyMINzo33qbdyjiNfYFx_hGWZXl9jwfHPwnsNze9usppOtuIgNFde8z0BHuJTDZz7TN7Ogi0ZmTnUV2NGlMxX9MbU1ZcqaIhx9ODJbQ7r61ow10pAZpHJOdPWNlGf06fsUhRsteZH-fbR978FM67_7T_K1aaIcZhW1zKkyXNSiUFMjPi66MtGjqH1gb72CCerq_GyI-BrD_A1XCj2DF78-b6h475LerWxEJGXaZs_48EJwB4zvMp3fK0xygg4BPFjJO0xSUVqqmz70w0W4sOKc5V7_JmvTMXoSuuuKHwuGq9r77p0eKUnr5U0DzMUKqTlxRsMtoNcT0OLtQ","iv":"Nn9CsSi0-tacUZEQ-vDC0w","ciphertext":"GYYpUaQwnV1jNDmwOTpQ6k3P5iCMMSju2x462YMiQsmboKnDMfxn-948Rs17SKwI4NGH8kB0zXVEDiiBSPEZnfcntt42txlFcFLwA7zzv1dj5tMUhQZoa3WvffMhugsOwmammM9FwKEq9Gi6U06JXSV8e9DmyvFRfGnNSnVgMO97P7_63tMpqiAjJJsqVfxdTgUj8rP0UV8V-QkQaDon01wCnwDP436GniCXYdfmH0MM9ExNwrtQL3VFZCAxDz6ZkaHi4S93KGNYtCtSYFQ_Gpk9c_82Mxerb5aATaVx9dGSAQcK5OIzwYEDB-QH2jXjxd68Z9LV86UNRWkx-MmRSLC2qjywR0qsLcZh4lZedk1bRJK3rPkP1NsvV3F30b-Y2vWfoSKufTTMjOD2Z20GdkakZ1H1r1YjO9sXfqEses0VhP_rfNdfgk-9zqxgyu2z5HY88m4rDn5zZXP4wlSGwvymOTFm8FSSUP_k96Jk_61Xhcyo5kGuAccoMwzGPBYmnHNyAUQRDUdxNtAx5o-fXNR58YdMEPEoog7zBj9usJJmh74pYtYt9OBbWLEWW9SOM-z6zICWgW3mM9I8erDaRU1x3UNYRLuTwUZU6brrh9E_yPReajLXxEaWid46qjF926mOGv7OvTKnB43PshY8N7hYPQZCSj-Pvelb61uINuH8AsN6fQV-_s_Gs8qjVM1Cy7_F0pdSVLo14ehZlpZKe7xbOw51-TJLnPAExWGQqq2L-I_s_YRQoY_HpoL4HepMO90dlrr0reKw6N0scQAQGq23P-1EwJvH375l3bEW1gemJkf2a8Z_FOiuvmCw69kq","tag":"s66_5GYp9UecmT2G76y7jA","aad":"ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pyYVdRaU9pSnRlVXRsZVVsa0lpd2laVzVqSWpvaVFURXlPRU5DUXkxSVV6STFOaUo5"}
```

**Decryption**

```java
JOSE.read(json, String.class, base64UrlEncodedSecret);
```

## More examples

See the following examples for sample code:

* [JSON Web Token examples](src/main/java/org/ietf/jose/jwt/examples.md)
* [JSON Web Signature examples](src/main/java/org/ietf/jose/jws/examples.md)
* [JSON Web Encryption examples](src/main/java/org/ietf/jose/jwe/examples.md)
* [JOSE utility class examples](docs/examples.md)

All code used in these examples is available under `src/test/java/org/ietf/jose/jw*/examples.md` and `src/test/java/org/ietf/jose/demo`. 

## JSON Object Signing and Encryption introductions

* [JSON Web Signatures](docs/about-jws.md)
* [JSON Web Encryption](docs/about-jwe.md)
* [JSON Web Tokens](docs/about-jwt.md)
* [JSON Web Keys](docs/about-jwk.md)
* [JSON Web Algorithms](docs/about-jwa.md)

# License

Copyright 2018 Key Bridge. Published under the Apache 2.0 license.

# References

 * [jwt.io](https://jwt.io/) - a catalog of open source JWT implementations
 * [jose4j](https://bitbucket.org/b_c/jose4j/overview) another complete implementation in Java




