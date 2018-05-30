# JSON Web Encryption (JWT) Code Examples

* [How to create](#jwe-create)
* [How to consume](#jwe-consume)
* [How to verify](#jwe-verify)

## <a name="jwe-create"></a> How to create a JSON Web Signature

```java
/**
 * Create a JSON Web Encryption object with a string as payload
 */
JweJsonFlattened jwe = JweBuilder.getInstance()
    .withStringPayload("hi")
    // sign it with our private key and specify a random UUID as the key ID
    .buildJweJsonFlattened(keyPair.getPublic());
String jweCompact = jwe.toCompactForm();

System.out.println("JWE JSON flattened:\n" + JsonMarshaller.toJsonPrettyFormatted(jwe));
System.out.println();
System.out.println("JWS compact form:\n" + jweCompact);
System.out.println();
```

**The output**

JWE JSON flattened:

```javascript
{
  "protected" : {
    "alg" : "RSA1_5",
    "enc" : "A128CBC-HS256"
  },
  "encrypted_key" : "CqB4JwpDDQ-9-lwcxGLFi-56uJAAfCJFBdNWItjhjdBnK0kRkiy5VMiQZYiw_ob5W7lQV1sIyq5yi3AAD8Fb8j7Su52XWKbLYU147kCkiqJhUMQS7Dr-Dsg01mVd9V_F08AYfeoUQzFjwIy4C1Erts1qdyI3apCTTlNxG_cFfmUEb_Rb9hMi5jdvxY82ZxeLEAjLm_UUdIs51CTgQG3T8KF8l6ZK5q3Kww4iLDE_gMUblGaZq4x6zZ_v4nFuhgdGYB8QSwXaF6NaiY7j8NjGYE4DmbQix8rD29Yye0iIeY4T2CwVynRhnr0m4cQQixsKIZrqfCOzfbNUaE1r89eINQ",
  "iv" : "4mo590rDMvZzLuK0nyXFWw",
  "ciphertext" : "nUzvDbLjjJ8vVIuqECWfzQ",
  "tag" : "lhd0thBl0kUZUcN1aonFOw",
  "aad" : "ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"
}
```

JWE compact form:

```
eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.CqB4JwpDDQ-9-lwcxGLFi-56uJAAfCJFBdNWItjhjdBnK0kRkiy5VMiQZYiw_ob5W7lQV1sIyq5yi3AAD8Fb8j7Su52XWKbLYU147kCkiqJhUMQS7Dr-Dsg01mVd9V_F08AYfeoUQzFjwIy4C1Erts1qdyI3apCTTlNxG_cFfmUEb_Rb9hMi5jdvxY82ZxeLEAjLm_UUdIs51CTgQG3T8KF8l6ZK5q3Kww4iLDE_gMUblGaZq4x6zZ_v4nFuhgdGYB8QSwXaF6NaiY7j8NjGYE4DmbQix8rD29Yye0iIeY4T2CwVynRhnr0m4cQQixsKIZrqfCOzfbNUaE1r89eINQ.4mo590rDMvZzLuK0nyXFWw.nUzvDbLjjJ8vVIuqECWfzQ.lhd0thBl0kUZUcN1aonFOw
```

## <a name="jwe-consume"></a> How to consume a JSON Web Signature

```java
// From compact form
FlattenedJsonSignature decodedFromCompactForm = FlattenedJsonSignature.fromCompactForm(jwsCompact);
// From JSON Flattened form
FlattenedJsonSignature decodedFromJsonFlattened = FlattenedJsonSignature.fromJson(jwsJsonFlattened);
// From JSON General form
GeneralJsonSignature decodedFromJsonGeneral = GeneralJsonSignature.fromJson(jwsJsonGeneral);
```

## <a name="jwe-verify"></a> How to verify a JSON Web Signature

A JWE object is implicitly validated during decryption. Unsuccessful decryption means that either an incorrect decryption key has been used or that the encrypted message has been tampered with and is invalid.