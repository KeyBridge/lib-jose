# JSON Web Signature (JWS) Code Examples

* [How to create](#jws-create)
* [How to consume](#jws-consume)
* [How to verify](#jws-verify)

## <a name="jws-create"></a> How to create a JSON Web Signature

```java
/**
 * Create a JSON Web Signature with a string as payload
 */
JwsBuilder jwsBuilder = JwsBuilder.getInstance()
    .withStringPayload("hi")
    // sign it with our private key and specify a random UUID as the key ID
    .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId);
String jwsJsonFlattened = jwsBuilder.buildJsonFlattened().toJson();
String jwsJsonGeneral = jwsBuilder.buildJsonGeneral().toJson();
String jwsCompact = jwsBuilder.buildCompact();

System.out.println("JWS JSON flattened:\n" + JsonMarshaller.toJsonPrettyFormatted(jwsBuilder.buildJsonFlattened()));
System.out.println();
System.out.println("JWS JSON general:\n" + JsonMarshaller.toJsonPrettyFormatted(jwsBuilder.buildJsonGeneral()));
System.out.println();
System.out.println("JWS compact form:\n" + jwsCompact);
System.out.println();
```

**The output**

JWS JSON flattened:

```javascript
{
  "payload" : "aGk",
  "protected" : {
    "alg" : "RS256",
    "kid" : "de0e6a7b-4afd-495c-9bba-495839a98e4b"
  },
  "signature" : "dpkd-C3ts51ju5z8rYFRvbFrCr1LVkybeM_DkiCbeGlsQ_F4nyaMA9i_AieuaGbQMLO_SJ61umuKD9XSVu-tTx3nAsnxurciPfOmneVVH2NMW-us42Mp9c41mOKCbawxJaqsGGjX4AsDxxYgQO_qzLudOiA-mfVTPKMDmITz9tSJzJdPmpsQsfo4CsHMr6Aosj329sSYU657ZG5DKvI8rPB79pb4lbT4R6EZIflsCpdLUmoLqVxOGmhlhzDjN0hBVeK9KyZgy5aVbdvMovTMqqKdNiaMG8OCHdNO5ekGPBMDgW62IA-81G1soTkFByo9N2m_wLnHL_mVh56WR_zIvw"
}
```

JWS JSON general:

```javascript
{
  "payload" : "aGk",
  "signatures" : [ {
    "signature" : "dpkd-C3ts51ju5z8rYFRvbFrCr1LVkybeM_DkiCbeGlsQ_F4nyaMA9i_AieuaGbQMLO_SJ61umuKD9XSVu-tTx3nAsnxurciPfOmneVVH2NMW-us42Mp9c41mOKCbawxJaqsGGjX4AsDxxYgQO_qzLudOiA-mfVTPKMDmITz9tSJzJdPmpsQsfo4CsHMr6Aosj329sSYU657ZG5DKvI8rPB79pb4lbT4R6EZIflsCpdLUmoLqVxOGmhlhzDjN0hBVeK9KyZgy5aVbdvMovTMqqKdNiaMG8OCHdNO5ekGPBMDgW62IA-81G1soTkFByo9N2m_wLnHL_mVh56WR_zIvw",
    "protected" : {
      "alg" : "RS256",
      "kid" : "de0e6a7b-4afd-495c-9bba-495839a98e4b"
    }
  } ]
}
```

JWS compact form:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlMGU2YTdiLTRhZmQtNDk1Yy05YmJhLTQ5NTgzOWE5OGU0YiJ9.aGk.dpkd-C3ts51ju5z8rYFRvbFrCr1LVkybeM_DkiCbeGlsQ_F4nyaMA9i_AieuaGbQMLO_SJ61umuKD9XSVu-tTx3nAsnxurciPfOmneVVH2NMW-us42Mp9c41mOKCbawxJaqsGGjX4AsDxxYgQO_qzLudOiA-mfVTPKMDmITz9tSJzJdPmpsQsfo4CsHMr6Aosj329sSYU657ZG5DKvI8rPB79pb4lbT4R6EZIflsCpdLUmoLqVxOGmhlhzDjN0hBVeK9KyZgy5aVbdvMovTMqqKdNiaMG8OCHdNO5ekGPBMDgW62IA-81G1soTkFByo9N2m_wLnHL_mVh56WR_zIvw
```

## <a name="jws-consume"></a> How to consume a JSON Web Signature

```java
// From compact form
FlattenedJsonSignature decodedFromCompactForm = FlattenedJsonSignature.fromCompactForm(jwsCompact);
// From JSON Flattened form
FlattenedJsonSignature decodedFromJsonFlattened = FlattenedJsonSignature.fromJson(jwsJsonFlattened);
// From JSON General form
GeneralJsonSignature decodedFromJsonGeneral = GeneralJsonSignature.fromJson(jwsJsonGeneral);
```

## <a name="jws-verify"></a> How to verify a JSON Web Signature

```java
boolean isValid = SignatureValidator.isValid(decodedFromCompactForm, keyPair.getPublic());
System.out.println("JWS is valid: " + isValid);
```