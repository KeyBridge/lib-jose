# JSON Web Signature (JWS) Code Examples

* [How to create](#jws-create)
* [How to consume](#jws-consume)
* [How to verify](#jws-verify)

See the [unit test](https://github.com/KeyBridge/lib-jose/blob/master/src/test/java/org/ietf/jose/jws/Examples.java) for a working example of the following code extracts. 

## <a name="jws-create"></a> How to create a JSON Web Signature

```java
/**
 * Create a JSON Web Signature with a string as payload
 */
privateKey = ... // the PrivateKey used for signing
JwsBuilder.Signable jwsBuilder = JwsBuilder.getInstance()
    .withStringPayload("hi")
    // sign it with our private key and specify a random UUID as the key ID
    .sign(privateKey, JwsAlgorithmType.RS256, keyId);

String jwsJsonGeneral = jwsBuilder.buildJsonWebSignature().toJson();
String jwsCompact = jwsBuilder.buildCompact();
```

**The output**

JWS JSON:

```javascript
{
  "payload" : "aGk",
  "protected" : "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU1M2U5YzJkLWQzYWMtNDQ1MS1iMThjLWY0M2YwYWRjNThhNyJ9",
  "signature" : "qkMrP-E6jjxMm0GWq8PgdWGiGP4VOhCnU4oYowrIT66vOHXn2im1a5civGEwpknWb08CJOvEObyCw6GN7S1ARfrywjk6QLToexgRyd2ehG8L1aYdEkvxGG4JE1yUtnNw1LI2EXgd5gTvFDsBw8cj5fOqDFAsqBKAkz_BiHPtE6PohIPe38ZPOABHe504tjAtRMQ6-ztKFUZcs_K2lLBp_jVGZk9uQR7l0ONaln0HFYu2Vl3UC5SgHqdn2qHl-23X_Vl0oTllsErYcRbd10RVdT-gcUvgqsGq043tA78fpBLKyV3A4SFT4XnmH_vC_28wIpDS8b6AeP6MvsvbECSseA"
}
```

Note that JSON Web Signatures are automatically serialized to JSON Flattened form when a single signature is present. Otherwise, a JSON General form JSON string is generated. 

JWS compact form:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU1M2U5YzJkLWQzYWMtNDQ1MS1iMThjLWY0M2YwYWRjNThhNyJ9.aGk.qkMrP-E6jjxMm0GWq8PgdWGiGP4VOhCnU4oYowrIT66vOHXn2im1a5civGEwpknWb08CJOvEObyCw6GN7S1ARfrywjk6QLToexgRyd2ehG8L1aYdEkvxGG4JE1yUtnNw1LI2EXgd5gTvFDsBw8cj5fOqDFAsqBKAkz_BiHPtE6PohIPe38ZPOABHe504tjAtRMQ6-ztKFUZcs_K2lLBp_jVGZk9uQR7l0ONaln0HFYu2Vl3UC5SgHqdn2qHl-23X_Vl0oTllsErYcRbd10RVdT-gcUvgqsGq043tA78fpBLKyV3A4SFT4XnmH_vC_28wIpDS8b6AeP6MvsvbECSseA
```

## <a name="jws-consume"></a> How to consume a JSON Web Signature

```java
// From compact form
JsonWebSignature decodedFromCompactForm = JsonWebSignature.fromCompactForm(jwsCompact);
// From JSON form
JsonWebSignature decodedFromJson = JsonWebSignature.fromJson(jwsJsonGeneral);
```

## <a name="jws-verify"></a> How to verify a JSON Web Signature

```java
boolean isValid = SignatureValidator.isValid(decodedFromCompactForm, keyPair.getPublic());
System.out.println("JWS is valid: " + isValid);
```