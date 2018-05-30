# Usage examples

This page provides some code examples. The full code is available in [this test class](../src/test/java/ch/keybridge/jose/demo/DemoTest.java).

## Signing and encryption

### Sign and encrypt using public/private keys

Example **input** to sign and encrypt:
```
String sampleText = "sample text to sign and encrypt";
```

The sender's private key is used to generate a digital signature of they payload, whereas the recipient's public key is used to encrypt the signed payload. The last argument is a string that will be set as the `kid` field in the protected header of the resulting JSON Web Encryption string and the contained JSON Web Signature. This information can be useful for the message recipient to determine what public key to use to validate the digital signature. 

```java
    String json = JOSE.SignAndEncrypt.write(sampleText, senderKeyPair.getPrivate(), recipientKeyPair.getPublic(),
        "myKeyId");
```

**Output**

```json
{"protected":{"alg":"RSA1_5","enc":"A128CBC-HS256"},"encrypted_key":"N4rQNjwKdNRRMOtnDLNadoW_DBVx9cpRGaUV2-5BuY4JtWsTpnRERyXmmR2C3B0xKwyIqM9yNHQc58w4BW1FXLFRC2mXyek-AaBsg_N_iH9oh_Bl5LBjyaaQCR9NxkevlrTYWkdaIcObiw4WUftwS6w3AlBWC8O2s0Ijy4HSmWYzGR7jgu7KrF_6kL1eytA5qjTLZSUkVAqbBQUwKI_atJZ6OPUjk-svtuFJct5qpe6xcoYnoQKnUgCMDPce7LRtiNV-zRKVMeTJQVMcAkR8c8ix-8m2ENai_LGzv_BpGdM4Tep9RsQSvn4vq9Y1IzrTZMwwyL-5gWNmqggttvkiFw","iv":"_cFNYka15EO_4SUhIfiA0A","ciphertext":"Ter0XwvbhyPxgL9ZJHTSB0nanxPAKMSZOeYy1GsRuxfTWjnwamxzsfACeNy-oYdvU0yzjS7DH8BzFZQ4ypiLDTwoghr0LI9nRQUF8PweXr61CG6AV9DE0rEMtLN3ZAV5wTjLFY1CDyE2Iik99mgRXjct1rBjKtLBKvMVFwzfjGklMBDs03ePjoeHHAboa_zY7y5DpXJlAg8_BwfGgg6C7v9798yRfyGaG8VguwUPytVhkcQOncNgxmMvCCUiaIkCZog20WlLx28alYFUe4juPCsmp6LfqGEgwc5F6_7uVTw0kBMWDfBikUKhg8p0aRDrJ85Y4QN4xZlFZDNpjTYf4HTN3gC1LqWza2lf0AUWksEHe6UGcqe09vIZfd5TgUcRm8s4WOr3I-3MGNLxNCIc82vZiEOPRxpMnQJNMgRj2yVgYB0nn0ONoEpWZ5L4s2p8USMepPqBuZ_I9vP9WYslSUxX9QNF7RELDRJsqqTYGNDV_sChjGnvA8I2p3vQe8um864jSQK3uzLaAfNNB74SoqmZvQYu4-zPNCGo9VTrOf_vpFGCB4ydBf4TWw3GsELaPnmCOD5sAwsFrPcP5ohfSr7CQOV9_EataWnHkGYUMSaZpMnEA0AnRp3mfLUG3ohuLcd4uUGuwbKgs0csOzLOKOXVx5GEdma2QI9vYMppKiKZgC55d6bMiegZiHkynzuE5KckUnGY1d0R1rqw_9tHEZGus5O8Vet2hnMcVBSM8FlAK8KK8rriO15dlEZN1DqRbsmMNAbbNLtIAyNAp3eIaHwxZBbbjez182SpuJs1wuH99RRTcX2JnL1pJPB6feQt","tag":"RAJW2iAzuD5mIG2X8zCdsw","aad":"ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"}
```

Similarly, to decrypt the payload, we need the recipient's private key, and the sender public key to validate the digital signature. Since the correct keys are used, we obtain a new object that is identical to the input object:

```java
JOSE.SignAndEncrypt.read(json, String.class, recipientKeyPair.getPrivate(), senderKeyPair.getPublic());
```

Decrypted result:

```
sample text to sign and encrypt
```

Note that the digital signature or HMAC are validated automatically by the JOSE::read method. 

### Sign and encrypt using a shared key

The **input** object:

```
String sampleText = "sample text to sign and encrypt";
```

```java
JOSE.SignAndEncrypt.write(sampleText, base64UrlEncodedSecret, "myKeyId")
```
The **output** is a signed and encrypted JSON:
```json
{"protected":{"alg":"A256KW","kid":"myKeyId","enc":"A128CBC-HS256"},"encrypted_key":"MvGbsX75DNZIVPCYl4z4kGgObVYSlNShRDlBYB1_CUN2Ea3FlA3tPA","iv":"Y7aSOG6vYIs7-ZrBWdC-EA","ciphertext":"M2zaOZdlx_qnQVWGZPNBhITGjAOfLaWDZexDKiwd6pmYnx68k6Vn-RMJLcgl2C35uQpbLage-9KXigFg5Xpyc939rU-LecrRvM0EPfr6toUhRwuEbZvJbln5lH6UTOgPu2K-fevVjMzMa41wLUi7cEkNXRob7_qvOXAcYoMofD_CKc477rwS0wieDpu61gLI7zifwjNh1RZ0fD5XyW9TuGxMhD8cJhOVDmwbgXHcXmBsx6EMuJ7ZCXT6MEVZmJsjsPdkLavrmo5Q8cUvn5myQWgalLZsuol-h4vAprVWY80","tag":"8qmXaWwqFXZYlEi454P4wA","aad":"ZXlKaGJHY2lPaUpCTWpVMlMxY2lMQ0pyYVdRaU9pSnRlVXRsZVVsa0lpd2laVzVqSWpvaVFURXlPRU5DUXkxSVV6STFOaUo5"}
```

This JSON string can be decrypted using the same shared secret. 

```java
JOSE.SignAndEncrypt.read(json, String.class, base64UrlEncodedSecret)
```

## Digital signatures and HMAC codes

### Signing with a keyed hash (HMAC)

**Input**: The string _sample text to sign_.

```java
JwsBuilder.getInstance()
        .withStringPayload(sampleText)
        .sign(base64UrlEncodedSecret, algorithm, UUID.randomUUID().toString())
        .buildJsonFlattened()
        .toJson();
```

**Output**

```json
{"payload":"c2FtcGxlIHRleHQgdG8gc2lnbg","protected":{"alg":"HS256","kid":"2800c8be-c1c7-47ff-834c-8e3e8b5fae8c"},"signature":"n8XlgS6VjBBEAPAbciGAYXbJrz9Wps1MUZ7_p-NuSzM"}
```

#### Signature validation

```java
FlattenedJsonSignature jws = FlattenedJsonSignature.fromJson(json);
    Assert.assertTrue(SignatureValidator.isValid(jws, base64UrlEncodedSecret));
```

### Digital signature

A private key of the sender is required for a digital signature. **Input**: The string _sample text to sign_.

```java
JwsBuilder.getInstance()
        .withStringPayload("sample text to sign")
        .sign(senderKeyPair.getPrivate(), JwsAlgorithmType.RS256, UUID.randomUUID().toString())
        .buildJsonFlattened()
        .toJson();
```

**Output**

```json
{"payload":"c2FtcGxlIHRleHQgdG8gc2lnbg","protected":{"alg":"RS256","kid":"17e590ef-91a4-4693-890c-0cd38addaea9"},"signature":"iZ0RsJgs0nIitRZlTb0HYRr6ntnj_l-RTM-4xA-aA1cCxqVD-Xkc-InXcZeuqmZHUExAal56J9pkTfl0oecPbb6JLDdNXkhbjMaBcCavnG1kyAd0pNgAvKhKU5uCoFiItR6Hkrk7lWkioFFofTKXjGLqPSGKOpgu4g74TWYrtI115KEuG3MEpAwQKed4kP-Wf3UpwPfCYGLjXMpUgUGhktOM8hQMYyoAJJsX3Pf_8QGYa3oLPaJlGqwL-tWFdru___hlkdVpcDiu3-GuY2Co98NidZqJakNfXtRpizUICY2SMd3NIvnReJRyRp62rPg9LuET3OhrUT9fZX7HLga3lw"}
```

#### Signature validation

```java
FlattenedJsonSignature jws = FlattenedJsonSignature.fromJson(json);
Assert.assertTrue(SignatureValidator.isValid(jws, senderKeyPair.getPublic()));
```
