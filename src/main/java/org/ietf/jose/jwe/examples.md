# JSON Web Encryption (JWT) Code Examples

* [How to create](#jwe-create)
* [How to consume](#jwe-consume)
* [How to verify](#jwe-verify)

See the [unit test](https://github.com/KeyBridge/lib-jose/blob/master/src/test/java/org/ietf/jose/jwe/Examples.java) for a working example of the following code extracts. 

## <a name="jwe-create"></a> How to create a JSON Web Encryption

```java
/**
 * Create a JSON Web Encryption object with a string as payload
 */
publicKey = ... // the recipient's public key used for wrapping (encrypting) the randomly generated content encryption key. 

JsonWebEncryption jwe = JweBuilder.getInstance()
    .withStringPayload("hi")
    .buildJweJsonFlattened(publicKey);  // sign it with our private key
String jweCompact = jwe.toCompactForm();

System.out.println("JWE JSON flattened:\n" + JsonMarshaller.toJsonPrettyFormatted(jwe));
System.out.println();
System.out.println("JWS compact form:\n" + jweCompact);
System.out.println();
```

**The output**

JWE JSON flattened:

```json
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

The above output is pretty-formatted. By default the generated JSON is not 
pretty-formatted (that is, the output JSON not contain spaces or new line 
symbols between JSON tokens). 

JWE compact form:

<pre>
  <span class="text-danger">eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0</span>.<span class="text-success">CqB4JwpDDQ-9-lwcxGLFi-56uJ
  AAfCJFBdNWItjhjdBnK0kRkiy5VMiQZYiw_ob5W7lQV1sIyq5yi3AAD8Fb8j7Su52XWKbLYU147kCk
  iqJhUMQS7Dr-Dsg01mVd9V_F08AYfeoUQzFjwIy4C1Erts1qdyI3apCTTlNxG_cFfmUEb_Rb9hMi5j
  dvxY82ZxeLEAjLm_UUdIs51CTgQG3T8KF8l6ZK5q3Kww4iLDE_gMUblGaZq4x6zZ_v4nFuhgdGYB8Q
  SwXaF6NaiY7j8NjGYE4DmbQix8rD29Yye0iIeY4T2CwVynRhnr0m4cQQixsKIZrqfCOzfbNUaE1r89
  eINQ</span>.<span class="text-info">4mo590rDMvZzLuK0nyXFWw.nUzvDbLjjJ8vVIuqECWfzQ.lhd0thBl0kUZUcN1aonFOw</span>
<pre>

## <a name="jwe-consume"></a> How to consume a JSON Web Encryption

```java
// From compact form
JsonWebEncryption fromCompact = JsonWebEncryption.fromCompactForm(jweCompact);
// From JSON Flattened form
JsonWebEncryption fromJson = JsonWebEncryption.fromJson(jwe.toJson());
```

## <a name="jwe-verify"></a> How to verify a JSON Web Encryption

A JWE object is implicitly validated during decryption. 
Unsuccessful decryption means that either an incorrect decryption key has been 
used or that the encrypted message has been tampered with and is invalid.
