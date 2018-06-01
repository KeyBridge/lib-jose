# Usage examples

This page provides some code examples. The full code is available in [this test class](https://github.com/KeyBridge/lib-jose/blob/master/src/test/java/org/ietf/jose/demo/DemoTest.java).

## Signing and encryption

### Sign and encrypt using public/private keys

Example **input** to sign and encrypt:
```
String sampleText = "sample text to sign and encrypt";
```

The sender's private key is used to generate a digital signature of they payload, whereas the recipient's public key is used to encrypt the signed payload. The last argument is a string that will be set as the `kid` field in the protected header of the resulting JSON Web Encryption string and the contained JSON Web Signature. This information can be useful for the message recipient to determine what public key to use to validate the digital signature. 

```java
senderPrivateKey = ... // sender's PrivateKey (for digital signing)
recipientPublicKey = ... // recipient's PublicKey (for encryption)
String json = JOSE.SignAndEncrypt.write(sampleText, senderPrivateKey, recipientPublicKey, "myKeyId");
```

**Output**

```javascript
{"protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"Vb9FW86Z5J3Kbcg-05I8qy1ADmeqD2MBDK0_7RosUaEtWLEvBeqgGxfQxLI5acjlrZbtsulUVxcOsiMg37MHqjIHhglCyDV8bdV2X9BlcyLyxe2xHqqPxZAn5KlY9vDptdx7djvZvfWPxnK3qaMTY5YKOflkHqzu5CLrQjHuvxvkDsjxDjPcl6_evrCqYaeJ45h_qzTDVaOoqSl3Z6Fv0az39h0jocSBwF4aIw_WpN2RXF787NPZe9gPzhsWudwYED_-bNhCbPssjF87j9ErPe8n0jGywXGc4oPAIZ7Ju0op1fQ_MedHNmZ7jOJgEbr-MWR5SlgqnqIZj6l_NR7MOA","iv":"-mFR5g_xCQKwTBPwCkQgbQ","ciphertext":"2N8nxhH9WPdrdjb1Ma7B2K3XXLnj6PIqDawR347HeFQS7XY-UVVl6qgvQy0zlwF2mblEgJiHkMxNPjnLC8URQpY9GsHcGEiCk9SmrKNqyX24f4dnStJFUTfQgpF7GsxEyOu4NGSYr4tmr7vpycW_WDgFIbZz5ZLc1PTcjazdwY8xiKNH4Jd_tJvBoLi4vYOVH1OzF6hWFSRkTSjbYRRF87XnsJwGBKH-56g1_MuI5FxXM9wYjsMeJNJ5hudsB7SMsdYYspDLVnuJ_wTHgf-tv3pi5yJCzp95Ai4L7G7CjLyWJFmEhxwuksLSk379TjeNO7RoEJWMBk_PuQ0XSoyF5OGfEMmZ7LMp2oXd1T6ccm6jf1rcqAZQuVg3koQWCGuK3hrwrTx5fhVixnuLEUlc-fGCKJZAvyHjxIDunFAsTeE6vDNecieLsedM6cTaXZ-xrJioYJXLlNAsrLq3VGuZxwSSVwzibsZ-LMwfJhJHvEiiHBjLXiKODW49e4Lol7eMRqBS1oi-BOrTW3EWP-BzkbTG_sDQJUmtf6lIfTGyZP-xb_YFbKPBtNUMNCh91tRUGK7n4s35x_aeFt-y4EtROH00z39BE6KsFTcB5_HP7cOQxsYJQV8zk52YKicth4EL","tag":"0jVcl-qMfMvW5SywFIbqRg","aad":"ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"}
```

Similarly, to decrypt the payload, we need the recipient's private key, and the sender public key to validate the digital signature. Since the correct keys are used, we obtain a new object that is identical to the input object:

```java
recipientPrivateKey = ... // recipient's PrivateKey (for decryption)
senderPublicKey = ... // sender's PublicKey (for signature validation)

JOSE.SignAndEncrypt.read(json, String.class, recipientPrivateKey, senderPublicKey);
```

Decrypted result: `sample text to sign and encrypt`

Note that the digital signature or HMAC are validated automatically by the JOSE::read method. 

### Sign and encrypt using a shared key

The **input** object:

```
String sampleText = "sample text to sign and encrypt";
```

```java
String json = JOSE.SignAndEncrypt.write(sampleText, base64UrlEncodedSecret, "myKeyId");```
```

The **output** is a signed and encrypted JSON:

```json
{"protected":"eyJhbGciOiJBMjU2S1ciLCJraWQiOiJteUtleUlkIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9","encrypted_key":"jFRwPoyk_FacqXzCArBs9qGQRMbbB_cFJiq0GCUK75ftWabXuPkkYw","iv":"58prHwsdTNDV-eh5UqwzHA","ciphertext":"OnOhDgZlnHpUPQ6IMs52KJh9jX-lS4HBKNrDkCWfWi1Zc2v0KIVkXk-3nKsxzEbt-ptxUadilbGqW4lXww_GssoB_85sL3wy8oEcROKd0yyKzWzgpsuluK-RNWVF0s0m_jvMWAW91q9GtYTNjqlPZ9jQNvj4QeedO1zsXXdDP8Kl6vNkKI2VN0hr8hn23cbKFfhc5mEu9RglXv7ZWeP2FsrCFYnWhAKCIlCDpBYEpQU","tag":"eBU3DvmSAvjxp1ntqXsqqg","aad":"ZXlKaGJHY2lPaUpCTWpVMlMxY2lMQ0pyYVdRaU9pSnRlVXRsZVVsa0lpd2laVzVqSWpvaVFURXlPRU5DUXkxSVV6STFOaUo5"}
```

This JSON string can be decrypted using the same shared secret. 

```java
String decrypted = JOSE.SignAndEncrypt.read(json, String.class, base64UrlEncodedSecret);
```

## Digital signatures and HMAC codes

### Signing with a keyed hash (HMAC)

**Input**: The string _sample text to sign_.

```java
JwsAlgorithmType algorithm = JwsAlgorithmType.HS256;
String base64UrlEncodedSecret = ... // BASE64URL-encoded bytes of the shared secret

JwsBuilder.getInstance()
        .withStringPayload("sample text to sign")
        .sign(base64UrlEncodedSecret, algorithm, UUID.randomUUID().toString())
        .buildJsonFlattened()
        .toJson();
```

**Output**

```json
{"payload":"c2FtcGxlIHRleHQgdG8gc2lnbg","protected":{"alg":"HS256","kid":"2800c8be-c1c7-47ff-834c-8e3e8b5fae8c"},"signature":"n8XlgS6VjBBEAPAbciGAYXbJrz9Wps1MUZ7_p-NuSzM"}
```

#### Consuming JSON

```java
JsonWebSignature jws = JsonWebSignature.fromJson(json);
```

#### Signature validation

```java
FlattenedJsonSignature jws = FlattenedJsonSignature.fromJson(json);
SignatureValidator.isValid(jws.getSignatures().get(0), base64UrlEncodedSecret)
```

### Digital signature

A private key of the sender is required for a digital signature. **Input**: The string _sample text to sign_.

```java
privateKey = ... // PrivateKey used for signing
String json = JwsBuilder.getInstance()
    .withStringPayload("sample text to sign")
    .sign(privateKey, JwsAlgorithmType.RS256, UUID.randomUUID().toString())
    .buildJsonWebSignature()
    .toJson();
```

**Output**

```json
{"payload":"c2FtcGxlIHRleHQgdG8gc2lnbg","protected":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2MzcxZTg1LTlhMDgtNDhmOC1iOTJhLTQ0OGQ4NGQxODI2YiJ9","signature":"J4jDwWDmyuGcrrcNTQvdbNWsP8zJ8s7H_M_wDbBF9qu2L4VwaTYsrdxY9wX4D3R-VGUaRKE14IwfBkYNxlsYjhnpD2hP9ueD7HZYUzPFK8hgEm0CZLWF-tIbfhXzw6ZhfTM51s0UMwiFR2Y06lJBVNWrVj8lGezgVbW6zP1egfoYGv4XAP0pCByrZPLzhP6ncROPX2etoElgBFdiTahf1htXcTx8AVX4wLRtKgh8gDRC6MaGyWi-fX___0cd8j3X4hYCmqd3sFjuhAmRrxFozL52imge0YHoFZNEpHBQl0kRsE2K3qw2ge0dPOuBHMW-cgGq3oPLTYSiJEs8dlKgtw"}
```

#### Consuming JSON

```java
JsonWebSignature jws = JsonWebSignature.fromJson(json);
```

#### Signature validation

```java
publicKey = ... // the public key counterpart of the PrivateKey used to sign
SignatureValidator.isValid(jws.getSignatures().get(0), publicKey)
```
