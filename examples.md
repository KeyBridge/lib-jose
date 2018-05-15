# Usage examples

This page provides some code examples. The full code is available in [this test class](src/test/java/ch/keybridge/jose/demo/DemoTest.java).

## Signing and encryption

### Sign and encrypt using public/private keys

Example **input** to sign and encrypt:
```
SasRegistrationRequest{url='http://localhost:8080', inet4Address='127.0.0.1', inet6Address='null', hardwareAddress='someHardwareAddress', os='null'}
```

The sender's private key is used to generate a digital signature of the payload, whereas the recipient's public key is used to encrypt the signed payload. 

```java
JOSE.write(registrationRequest, senderPrivateKey, recipientPublicKey, "senderId");
```

**Output**

```json
{"protected":{"alg":"RSA1_5","enc":"A128CBC-HS256"},"encrypted_key":"Qszc4pd5P1ZqPsweDEuxTQ03uUOXz_otppdz_W2zua3ndEzRTw_xnsZ2jUKoyW-_oVK24YeOcfmOaLRJTtJWKGRwDE8UoXML8gwiZ2oQ_85FwaTzant8QDKFW0YOkbtlgToY8JkPKS04ZSaAtqvcI1gYeqlRz3w3AiP048wGV3ST4E43Ir-DTuJ_PzDJMPBP7j6REKLFaQMsrats6FhyHMSM-ZQubvCCZ7ilVnDi7ATakWnIoFjJ13OolDkB39rDD0_Pf_A94IezMvdtHvo-8lRNyNFrMe3BufJkpxsCGDyi7r5Sb8J8FOFp_ChAZ3vWFV_HSSOGsVNgW--qxxm6Fg","iv":"54AbYKpAGSOlFPslIiN5lw","ciphertext":"cycsEXeumOfgib3rODV-JUobxdLp4FKWcPgfRELdw_PEagiG048IUu5_6c6EnND2oqNNjNN6vkLKdE0nnZi2tl2W29MesQ3e-Hv2WfSSKSq80eBdr7ASz6oEfp6vKY8h9SqkniV0A93pmYHV9zw4CQJGHnOHPLATBgi8kdKXrc6-wIU85XsXxdM9cIjTvKkzD2MZuyjUBYuQcgngQrH0eZBpt45oI59aGuboPzzSrcwO3orQCmUx_IJms78QbT3dlqi2I6f5OVcJ0Ippu_iWb17W_4nsAW87m84TFHGVKHh4Jr5cPYxm3q5rYVYBCkf2A_3nwDmDn7FWsGd4JfYx7mbLXxoKmHvTxM8JtzxN5mwqA_O3ZIaBkrAxeVgHje4tMWcbCfMD7Loz1yEk_vAW5NkWQh0XfblGSdQMSKqiFF9dluH9sTAQ7_r8rA2fgf6S7EJrjli7bGmzGnZeSoJP8NsLJ2voM-yp6OUnDKauG7YPViVGj2AtKxotr1BuVyms1iSxD-IGE7fHtEb-eEoOvWcMb9t16GFSr4gbCe86JpxrUH8OcaqPqmbDU4Lm6DlscufOzs5ZB4bAuSyivv4e35yX_sRzPnnNAEgrtY2lsHAnL1F5R-TroXRqYSvml-nu79fPHdJGYwTcoDDrK9Fli6kD17iOboOsH17L5KDQk6SSRtvjVg4K9JV-AAIZQnNWoHXJfxOR20FV1EjwRc7vNCrBhI2Jl_sQqk9K9sfcdZgJqorOKudCRhn9X1oiL1gnfbTW8aJzchcUmgwQ3h4UMRHG3NYHsxjcvu1xJ0UWeXiaChvuIWGwvDpKV0aBSgSRkPMXPDgza85Z6-z9JFvZ1WTHvs76mNxCi_pmyKtbxaizS4xs-XLqmeXg6PvdgGiHmAQ0n0SVtY7bwBtwQXBOHpIRuKOKtmuxGltjn2dXXYH7bIRQ3xaUf6N9q5KpPjqFjfspWjazKsWeksfw4mNOUw","tag":"jVqU_7ebrwRM6pPpqjRjOA","aad":"ZXlKaGJHY2lPaUpTVTBFeFh6VWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"}
```

Similarly, to decrypt the payload, we need the recipient's private key, and the sender public key to validate the digital signature. Since the correct keys are used, we obtain a new object that is identical to the input object:

```java
JOSE.read(json, SasRegistrationRequest.class, recipientPrivateKey, senderPublicKey)
```

```
SasRegistrationRequest{url='http://localhost:8080', inet4Address='127.0.0.1', inet6Address='null', hardwareAddress='someHardwareAddress', os='null'}
```

### Sign and encrypt using a shared key

The **input** object:

```
EscNotificationMessage{dpaId='DPA002', name='null', description='null', active=true, channelName='CBRS5', frequencyMin=null, frequencyMax=null}
```

```java
JOSE.write(message, base64UrlEncodedSecret, "senderId")
```
The **output** is a signed and encrypted JSON:
```json
{"protected":{"alg":"A256KW","enc":"A128CBC-HS256"},"encrypted_key":"WMb9eXeuwWqC6X-EpraETyrocXHPsquMlBdF5whNgePEjIUXIhnaLw","iv":"L1wiiNL8N2D5dZ8zEHuhTg","ciphertext":"rZunE0B4VtxKqjFBuEdjUAK0SN3kDNtVya0DpUmwKUGBweo6LBZQA9ADredcH2flBUPceZMqGzxqZapez-gfMfQe0UEUA9ubEolyBxOdoBd0jInqFE3630uj1cmCCV9GFc4oQkfgHYku1MSflSFTczff3EUL0ZbERgYDF-ImOVv2niTeQRBToHODWYgof-m-pNsvxbNgtCpCbiOskxx1MZtjMXq6QB6rruAC7Id8YXzWbnAUTp8xdPymAP3AB6MjlqlytwyG02kJIknkom2HK7pvEdm1glaTi4-IGK1OixlLXitQeh9BDKGOHeGSsOacqi_oh5i98ivF_VEYXls3ZA","tag":"2Hp2DdMZW8KYwYUlJo2M9A","aad":"ZXlKaGJHY2lPaUpCTWpVMlMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"}
```

This JSON string can be decrypted using the same shared secret. 

```java
JOSE.read(json, EscNotificationMessage.class, base64UrlEncodedSecret);
```

## Digital signatures and HMAC codes

### Signing with a keyed hash (HMAC)

**Input**: The string _Some payload_.

```java
JwsBuilder.getInstance()
        .withStringPayload("Some payload")
        .sign(base64UrlEncodedSecret)
        .buildJsonFlattened()
        .toJson();
```

**Output**

```json
{"payload":"U29tZSBwYXlsb2Fk","protected":{"alg":"HS256"},"signature":"OXVGGjYc_mMheGAgTfb4MgJeymhjWLVFlNzCAv7y3Zo"}
```

#### Signature validation

```java
JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), base64UrlEncodedSecret));
```

### Digital signature

A private key of the sender is required for a digital signature. **Input**: The string _Some payload_.

```java
JwsBuilder.getInstance()
        .withStringPayload("Some payload")
        .sign(senderPrivateKey, ESignatureAlgorithm.RS256)
        .buildJsonFlattened()
        .toJson();
```

**Output**

#### Signature validation

```java
JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), senderKeyPair.getPublic()));
```
