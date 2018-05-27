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
JOSE.write(sampleText, senderPrivateKey, recipientPublicKey, "myKeyId");
```

**Output**

```json
{"protected":{"alg":"RSA1_5","kid":"myKeyId","enc":"A128CBC-HS256"},"encrypted_key":"jgz9i1TlyMINzo33qbdyjiNfYFx_hGWZXl9jwfHPwnsNze9usppOtuIgNFde8z0BHuJTDZz7TN7Ogi0ZmTnUV2NGlMxX9MbU1ZcqaIhx9ODJbQ7r61ow10pAZpHJOdPWNlGf06fsUhRsteZH-fbR978FM67_7T_K1aaIcZhW1zKkyXNSiUFMjPi66MtGjqH1gb72CCerq_GyI-BrD_A1XCj2DF78-b6h475LerWxEJGXaZs_48EJwB4zvMp3fK0xygg4BPFjJO0xSUVqqmz70w0W4sOKc5V7_JmvTMXoSuuuKHwuGq9r77p0eKUnr5U0DzMUKqTlxRsMtoNcT0OLtQ","iv":"Nn9CsSi0-tacUZEQ-vDC0w","ciphertext":"GYYpUaQwnV1jNDmwOTpQ6k3P5iCMMSju2x462YMiQsmboKnDMfxn-948Rs17SKwI4NGH8kB0zXVEDiiBSPEZnfcntt42txlFcFLwA7zzv1dj5tMUhQZoa3WvffMhugsOwmammM9FwKEq9Gi6U06JXSV8e9DmyvFRfGnNSnVgMO97P7_63tMpqiAjJJsqVfxdTgUj8rP0UV8V-QkQaDon01wCnwDP436GniCXYdfmH0MM9ExNwrtQL3VFZCAxDz6ZkaHi4S93KGNYtCtSYFQ_Gpk9c_82Mxerb5aATaVx9dGSAQcK5OIzwYEDB-QH2jXjxd68Z9LV86UNRWkx-MmRSLC2qjywR0qsLcZh4lZedk1bRJK3rPkP1NsvV3F30b-Y2vWfoSKufTTMjOD2Z20GdkakZ1H1r1YjO9sXfqEses0VhP_rfNdfgk-9zqxgyu2z5HY88m4rDn5zZXP4wlSGwvymOTFm8FSSUP_k96Jk_61Xhcyo5kGuAccoMwzGPBYmnHNyAUQRDUdxNtAx5o-fXNR58YdMEPEoog7zBj9usJJmh74pYtYt9OBbWLEWW9SOM-z6zICWgW3mM9I8erDaRU1x3UNYRLuTwUZU6brrh9E_yPReajLXxEaWid46qjF926mOGv7OvTKnB43PshY8N7hYPQZCSj-Pvelb61uINuH8AsN6fQV-_s_Gs8qjVM1Cy7_F0pdSVLo14ehZlpZKe7xbOw51-TJLnPAExWGQqq2L-I_s_YRQoY_HpoL4HepMO90dlrr0reKw6N0scQAQGq23P-1EwJvH375l3bEW1gemJkf2a8Z_FOiuvmCw69kq","tag":"s66_5GYp9UecmT2G76y7jA","aad":"ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0pyYVdRaU9pSnRlVXRsZVVsa0lpd2laVzVqSWpvaVFURXlPRU5DUXkxSVV6STFOaUo5"}
```

Similarly, to decrypt the payload, we need the recipient's private key, and the sender public key to validate the digital signature. Since the correct keys are used, we obtain a new object that is identical to the input object:

```java
JOSE.read(json, String.class, recipientPrivateKey, senderPublicKey)
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
JOSE.write(sampleText, base64UrlEncodedSecret, "myKeyId")
```
The **output** is a signed and encrypted JSON:
```json
{"protected":{"alg":"A256KW","kid":"myKeyId","enc":"A128CBC-HS256"},"encrypted_key":"7MfrXslfmPe6yUllS5HDtlPz2ZnceIugdEBpsiCTnSGba_NNC7rhAA","iv":"S8RcvZT0IozDs9us5Tt9Sw","ciphertext":"m7-VYbLS0nBZczji7PYGstlKTgMYmxWNr3TRFS8fOWLzC9YLe3bJ9u0j06IqimtG1TadnjtrlfwVNjn4Bl13oSxGablMIcm_NZ1USUvvdb1mjySrTGLKmE_3TmeycgObg5JhiHzE9nApbcMHrkeHW_jtMtucF1ko7mF8y_70Yca5qrPu-UWzC_rf-8-ZwGaJG0jtQzEKEAU32A5bwm2YYLVtq83tYNgfm25xwKMOMEUCxvO12N3quHeWdc-guWGGeEbkVh5l72Q1JuMFj1_wp0Z0QqVU8oGLm6UWjdGwjqQ","tag":"IFHKhFJLkcWnVW0KiKKtiQ","aad":"ZXlKaGJHY2lPaUpCTWpVMlMxY2lMQ0pyYVdRaU9pSnRlVXRsZVVsa0lpd2laVzVqSWpvaVFURXlPRU5DUXkxSVV6STFOaUo5"}
```

This JSON string can be decrypted using the same shared secret. 

```java
JOSE.read(json, String.class, base64UrlEncodedSecret);
```

## Digital signatures and HMAC codes

### Signing with a keyed hash (HMAC)

**Input**: The string _sample text to sign_.

```java
JwsBuilder.getInstance()
        .withStringPayload("sample text to sign")
        .sign(base64UrlEncodedSecret)
        .buildJsonFlattened()
        .toJson();
```

**Output**

```json
{"payload":"c2FtcGxlIHRleHQgdG8gc2lnbg","protected":{"alg":"HS256"},"signature":"EMNWZQpxGe4ksgwgallrgxMUxv_-HjpL1Hd4M3_lo68"}
```

#### Signature validation

```java
JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), base64UrlEncodedSecret));
```

### Digital signature

A private key of the sender is required for a digital signature. **Input**: The string _sample text to sign_.

```java
JwsBuilder.getInstance()
        .withStringPayload("sample text to sign")
        .sign(senderPrivateKey, ESignatureAlgorithm.RS256)
        .buildJsonFlattened()
        .toJson();
```

**Output**

```json
{"payload":"U29tZSBwYXlsb2Fk","protected":{"alg":"RS256"},"signature":"TRBIaOxht-_6v9f7gnoJyr4bUtZTZbijKMx-slsqhUU6rGapvjddnh2qOzeai8ZkDQPv_AKiRet1XbEVG_Zasqd7Sbg55PuvL9Z4oW6iluNAGJXzUPfLE6ZqF-D6RPf1i680hdoC1lyPJexU1BiowoNPtgz9MBdWvgEnOc0TgWsS_XF57LbSxZve6uk8XPuuAx5grocpDzU5SxA27CGMyvg-CpHuIlOtGNflslD6GfePBtkM_-qqVej9dzSf0cW-9HM8mym7RoXGrGBZbf9SBYHGLhQ1oMPPOxUxSPzpFZPGy7fBmWrasubbTQCfQhyzjeOGSBUFvm7WE8qiILqc3w"}
```

#### Signature validation

```java
JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), senderKeyPair.getPublic()));
```
