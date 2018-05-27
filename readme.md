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


# More examples

See the [examples](doc/examples.md) for sample code.


## JWK - JSON Web Key

JSON Web Key is a data structure representing a cryptographic key with both the cryptographic data and other attributes, such as key usage.

```
{ 
  "kty":"EC",
  "crv":"P-256",
  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "use":"enc",
  "kid":"1"
}
```

Mandatory "kty" key type parameter describes the cryptographic algorithm associated with the key. Depending on the key type, other parameters might be used - as shown in the example elliptic curve key would contain "crv" parameter identifying the curve, "x" and "y" coordinates of point, optional "use" to denote intended usage of the key and "kid" as key ID. The specification now describes three key types: "EC" for Elliptic Curve, "RSA" for, well, RSA, and "oct" for octet sequence denoting the shared symmetric key.

## JWS - JSON Web Signature

JSON Web Signature standard describes process of creation and validation of datastructure representing signed payload. As example take following string as a payload:

```
{
 "iss":"joe",
 "exp":1300819380,
 "http://example.com/is_root":true
 }
```

Incidentally, this string contains JSON data, but this is not relevant for the signing procedure and it might as well be any data. Before signing, the payload is always converted to base64url encoding:

```
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLm
NvbS9pc19yb290Ijp0cnVlfQ
```

Additional parameters are associated with each payload. Required parameter is "alg", which denotes the algorithm used for generating a signature (one of the possible values is "none" for unprotected messages). The parameters are included in final JWS in either protected or unprotected header. The data in protected unprotectedHeader is integrity protected and base64url encoded, whereas unprotected unprotectedHeader human readable associated data.

As example, the protected header will contain following data:

```
{"alg":"ES256"}
```

which in base64url encoding look like this:

eyJhbGciOiJFUzI1NiJ9

The "ES356" here is identifier for ECDSA signature algorithm using P-256 curve and SHA-256 digest algorithm.

Unprotected header can contain a key id parameter:

```
{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}
```

The base64url encoded payload and protected header are concatenated with '.' to form a raw data, which is fed to the signature algorithm to produce the final signature.

Finally, the JWS output is serialized using one of JSON or Compact serializations. Compact serialization is simple concatenation of comma separated base64url encoded protected header, payload and signature. JSON serialization is a human readable JSON object, which for the example above would look like this:

```
{
  "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6
              Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  "protected":"eyJhbGciOiJFUzI1NiJ9",
  "header":
    {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
     "signature":
     "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
      lSApmWQxfKTUJqPP3-Kg6NU1Q"
}
```

Such process for generating signature is pretty straightforward, yet still supports some advanced use-cases, such as multiple signatures with separate headers.

## JWE - JSON Web Encryption

JSON Web Encryption follows the same logic as JWS with a few differences:

  *  by default, for each message new content encryption key (CEK) should be generated. This key is used to encrypt the plaintext and is attached to the final message. Public key of recipient or a shared key is used only to encrypt the CEK (unless direct encryption is used, see below).
  *  only AEAD (Authenticated Encryption with Associated Data) algorithms are defined in the standard, so users do not have to think about how to combine JWE with JWS.

Just like with JWS, header data of JWE object can be transmitted in either integrity protected, unprotected or per-recipient unprotected unprotectedHeader. The final JSON serialized output then has the following structure:

```
{
  "protected": "<integrity-protected header contents>",
  "unprotected": <non-integrity-protected header contents>,
  "recipients": [
    {"header": <per-recipient unprotected unprotectedHeader 1 contents>,
     "encrypted_key": "<encrypted key 1 contents>"},
     ...
    {"header": <per-recipient unprotected unprotectedHeader N contents>,
     "encrypted_key": "<encrypted key N contents>"}],
  "aad":"<additional authenticated data contents>",
  "iv":"<initialization vector contents>",
  "ciphertext":"<ciphertext contents>",
  "tag":"<authentication tag contents>"
}
```

The CEK is encrypted for each recipient separately, using different algorithms. This gives us ability to encrypt a message to recipients with different keys, e.g. RSA, shared symmetric and EC key.

The two used algorithms need to be specified as a header parameters. "alg" parameter specified the algorithm used to protect the CEK, while "enc" parameter specifies the algorithm used to encrypt the plaintext using CEK as key. Needless to say, "joseAlgorithmName" can have a value of "dir", which marks direct usage of the key, instead of using CEK.

As example, assume we have RSA public key of the first recipient and share a symmetric key with second recipient. The "alg" parameter for the first recipient will have value "RSA1_5" denoting RSAES-PKCS1-V1_5 algorithm and "A128KW" denoting AES 128 Keywrap for the second recipient, along with key IDs:

```
{"alg":"RSA1_5","kid":"2011-04-29"}
```

and

```
{"alg":"A128KW","kid":"7"}
```

These algorithms will be used to encrypt content encryption key (CEK) to each of the recipients. After CEK is generated, we use it to encrypt the plaintext with AES 128 in CBC mode with HMAC SHA 256 for integrity:

```
{"enc":"A128CBC-HS256"}
```

We can protect this information by putting it into a protected header, which, when base64url encoded, will look like this:

```
eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
```

This data will be fed as associated data to AEAD encryption algorithm and therefore be protected by the final signature tag.

Putting this all together, the resulting JWE object will looks like this:

```
{
  "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  "recipients":[
    {"header": {"alg":"RSA1_5","kid":"2011-04-29"},
     "encrypted_key":
       "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
        kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
        GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
        YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
        cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
        wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
    {"header": {"alg":"A128KW","kid":"7"},
     "encrypted_key":
        "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
  "iv": "AxY8DCtDaGlsbGljb3RoZQ",
  "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
  "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
}
```

## JWA - JSON Web Algorithms

JSON Web Algorithms defines algorithms and their identifiers to be used in JWS and JWE. The three parameters that specify algorithms are "alg" for JWS, "joseAlgorithmName" and "enc" for JWE.

 * **enc**  
      A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (AES in CBC with HMAC), 
      A128GCM, A192GCM, A256GCM

 * **"alg" for JWS**   
      HS256, HS384, HS512 (HMAC with SHA), 
      RS256, RS384, RS512 (RSASSA-PKCS-v1_5 with SHA), 
      ES256, ES384, ES512 (ECDSA with SHA), 
      PS256, PS384, PS512 (RSASSA-PSS with SHA for digest and MGF1)

 * **"alg" for JWE**  
      RSA1_5, RSA-OAEP, RSA-OAEP-256, 
      A128KW, A192KW, A256KW (AES Keywrap), 
      dir (direct encryption), 
      ECDH-ES (EC Diffie Hellman Ephemeral+Static key agreement), 
      ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW (with AES Keywrap), 
      A128GCMKW, A192GCMKW, A256GCMKW (AES in GCM Keywrap), 
      PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW 
      (PBES2 with HMAC SHA and AES keywrap)

On the first look the wealth of choice for "alg" in JWE is balanced by just two options for "enc". Thanks to "enc" and "alg" being separate, algorithms suitable for encrypting cryptographic key and content can be separately defined. AES Keywrap scheme defined in RFC 3394 is a preferred way to protect cryptographic key. The scheme uses fixed value of IV, which is checked after decryption and provides integrity protection without making the encrypted key longer (by adding IV and authentication tag). But here`s a catch - while A128KW refers to AES Keywrap algorithm as defined in RFC 3394, word "keywrap" in A128GCMKW is used in a more general sense as synonym to encryption, so it denotes simple encryption of key with AES in GCM mode.

## JWT - JSON Web Token

While previous parts of JOSE provide a general purpose cryptographic primitives for arbitrary data, JSON Web Token standard is more tied to the OpenID Connect. JWT object is simply JSON hash with claims, that is either signed with JWS or encrypted with JWE and serialized using compact serialization. Beware of a terminological quirk - when JWT is used as plaintext in JWE or JWS, it is referred to as nested JWT (rather than signed, or encrypted).

JWT standard defines claims - name/value pair asserting information about subject. The claims include

    "iss" to identify issuer of the claim
    "sub" identifying subject of JWT
    "aud" (audience) identifying intended recipients
    "exp" to mark expiration time of JWT
    "nbf" (not before) to mark time before which JWT must be rejected
    "iat" (issued at) to mark time when JWT was created
    "jti" (JWT ID) as unique identifier for JWT

While standard mandates what are mandatory values of the claims, all of them are optional to use in a valid JWT. This means applications can use any structure for JWT if it`s not intended to use publicly, and for public JWT set of claims is defined and collisions in names are prevented.


# License

Copyright 2018 Key Bridge. Published under the Apache 2.0 license.

# References

 * [jwt.io](https://jwt.io/) - a catalog of open source JWT implementations
 * [jose4j](https://bitbucket.org/b_c/jose4j/overview) another complete but poorly documented implementation in java




