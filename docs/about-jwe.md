## JWE – JSON Web Encryption

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

```javascript
{
  "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  "recipients":[
    {"header": {"alg":"RSA1_5","kid":"2011-04-29"},
     "encrypted_key":
       "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
    {"header": {"alg":"A128KW","kid":"7"},
     "encrypted_key":
        "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
  "iv": "AxY8DCtDaGlsbGljb3RoZQ",
  "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
  "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
}
```