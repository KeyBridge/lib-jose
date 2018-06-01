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


## Hello World JWE example

**Sign and encrypt**

Start with a clear text input and a set of keys.

```java
String sampleText = "sample text to sign and encrypt";

// the private key of the sender; it is used to digitally sign the message
PrivateKey privateKey = ... 
// the public key of the recipient; it is used to encrypt the message
PublicKey recipientPublicKey = ... 
// the signature key ID to be written as the 'kid' (key ID) field of the JWS protected header. Can be null.
String keyId = ... 

// SignAndEncrypt.write produces a a valid JSON string; null on error
String json = JOSE.SignAndEncrypt.write(sampleText, 
                                        senderPrivateKey, 
                                        recipientPublicKey, 
                                        keyId);
```

The signed and encrypted JSON output looks like (formatted for readability):

```javascript
{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
   "encrypted_key":"Vb9FW86Z5J3Kbcg-05I8qy1ADmeqD2MBDK0_7RosUaEtWLEvBeqgGxfQxLI5acjlrZbtsulUVxcOsiMg37MHqjIHhglCyDV8bdV2X9BlcyLyxe2xHqqPxZAn5KlY9vDptdx7djvZvfWPxnK3qaMTY5YKOflkHqzu5CLrQjHuvxvkDsjxDjPcl6_evrCqYaeJ45h_qzTDVaOoqSl3Z6Fv0az39h0jocSBwF4aIw_WpN2RXF787NPZe9gPzhsWudwYED_-bNhCbPssjF87j9ErPe8n0jGywXGc4oPAIZ7Ju0op1fQ_MedHNmZ7jOJgEbr-MWR5SlgqnqIZj6l_NR7MOA",
  "iv":"-mFR5g_xCQKwTBPwCkQgbQ",
  "ciphertext":"2N8nxhH9WPdrdjb1Ma7B2K3XXLnj6PIqDawR347HeFQS7XY-UVVl6qgvQy0zlwF2mblEgJiHkMxNPjnLC8URQpY9GsHcGEiCk9SmrKNqyX24f4dnStJFUTfQgpF7GsxEyOu4NGSYr4tmr7vpycW_WDgFIbZz5ZLc1PTcjazdwY8xiKNH4Jd_tJvBoLi4vYOVH1OzF6hWFSRkTSjbYRRF87XnsJwGBKH-56g1_MuI5FxXM9wYjsMeJNJ5hudsB7SMsdYYspDLVnuJ_wTHgf-tv3pi5yJCzp95Ai4L7G7CjLyWJFmEhxwuksLSk379TjeNO7RoEJWMBk_PuQ0XSoyF5OGfEMmZ7LMp2oXd1T6ccm6jf1rcqAZQuVg3koQWCGuK3hrwrTx5fhVixnuLEUlc-fGCKJZAvyHjxIDunFAsTeE6vDNecieLsedM6cTaXZ-xrJioYJXLlNAsrLq3VGuZxwSSVwzibsZ-LMwfJhJHvEiiHBjLXiKODW49e4Lol7eMRqBS1oi-BOrTW3EWP-BzkbTG_sDQJUmtf6lIfTGyZP-xb_YFbKPBtNUMNCh91tRUGK7n4s35x_aeFt-y4EtROH00z39BE6KsFTcB5_HP7cOQxsYJQV8zk52YKicth4EL",
  "tag":"0jVcl-qMfMvW5SywFIbqRg",
  "aad":"ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"
}
```

**Validate and decrypt**

Start with the signed and encrypted JSON string (above).

```java
// the recipient's private key; it is used to decrypt message
recipientPrivateKey = ... // recipient's PrivateKey (for decryption)
// the sender's public key; it is used to validate the digital signature
senderPublicKey = ... // sender's PublicKey (for signature validation)

// SignAndEncrypt.read produces a decrypted object of the specified class type
// Returns null if the signature fails to validate or the payload fails to decrypt. 
String recoveredSampleText = JOSE.SignAndEncrypt.read(json, 
                                                      String.class, 
                                                      recipientPrivateKey, 
                                                      senderPublicKey);
```

## More examples

See the following examples for useful sample code:

* [JSON Web Token examples](src/main/java/org/ietf/jose/jwt/examples.md)
* [JSON Web Signature examples](src/main/java/org/ietf/jose/jws/examples.md)
* [JSON Web Encryption examples](src/main/java/org/ietf/jose/jwe/examples.md)
* [JOSE utility class examples](docs/examples.md)

All code used in these examples is available under `src/test/java/org/ietf/jose/jw*/examples.md` and `src/test/java/org/ietf/jose/demo`. 

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
