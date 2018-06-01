# JSON Web Token (JWT) Code Examples

* [Signed JSON Web Tokens](#signed)
    * [How to create](#signed-create)
    * [How to consume](#signed-consume)
    * [How to verify](#signed-verify)
* [Encrypted JSON Web Tokens](#encrypted)
    * [How to create](#encrypted-create)
    * [How to consume](#encrypted-consume)
    * [How to verify](#encrypted-verify)

## <a name="signed"></a> Signed JSON Web Tokens

### <a name="signed-create"></a> How to create a signed JWT

```java
/**
 * Create a JWT claims set object. Please refer to RFC 7519 § 4.1. Registered Claim Names for details
 * about each claim.
 *
 * Note the use of chained setters.
 */
JwtClaims joseClaims = new JwtClaims()
    .setIssuer("Issuer")
    .setAudience("Audience");
// Set the expiration time of this JWT to be two hours from now
joseClaims.setExpirationTime(Instant.now().plus(2, ChronoUnit.HOURS));
// A JWT must be processed on or after the Not Before values. Let's set this to one minute from now
joseClaims.setNotBefore(Instant.now().minus(1, ChronoUnit.MINUTES));
joseClaims.setIssuedAt(Instant.now());
/**
 * The JWT ID is used a nonce to prevent replay attacks. It is recommended to use a random UUID
 */
joseClaims
    .setJwtId(UUID.randomUUID().toString())
    .setSubject("Subject");

/**
 * Custom claims are also supported.
 */
joseClaims
    .addClaim("domain", "somedomain.com")
    .addClaim("email", "someone@somedomain.com");

/**
 * Convert the JWT Claims objects to JSON
 */
String joseClaimsJson = joseClaims.toJson();

System.out.println("Claims:");
System.out.println(joseClaimsJson);
System.out.println();

/**
 * Create a JSON Web Signature with the serialized JWT Claims as payload.
 */
JwsBuilder.Signable jwsBuilder = JwsBuilder.getInstance()
    .withStringPayload(joseClaimsJson)
    // sign it with our private key
    .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId);
String jwt = jwsBuilder.buildCompact();
System.out.println("JWT:");
System.out.println(jwt);
System.out.println();
```

### <a name="signed-consume"></a> How to consume a signed JWT

```java
/**
 * Consume the JWT
 */
JwtReader jwtDecoded = JwtReader.readCompactForm(jwt);
/**
 * The JWT can be either a JWS (JSON Web Signature) or a JWE (JSON Web Encryption) object,
 * and the type can be determined with JWT::getType.
 */
assertEquals(JwtReader.Type.Signed, jwtDecoded.getType());
/**
 * In this instance we have a JWS.
 */
JsonWebSignature decodedFromCompactForm = jwtDecoded.getJsonWebSignature();
/**
 * Get the payload as string:
 */
String payload = decodedFromCompactForm.getStringPayload();
System.out.println("JWT Claims as JSON: " + payload);
/**
 * Deserialize the payload as a JwtClaims object
 */
JwtClaims claims = JwtClaims.fromJson(payload);
```

### <a name="signed-verify"></a> How to verify a signed JWT

```java
/**
 * Validate the JWT by using the SignatureValidator class
 */
boolean isValid = SignatureValidator.isValid(decodedFromCompactForm.getSignatures().get(0), keyPair.getPublic());;
```

## <a name="encrypted"></a> Encrypted JSON Web Tokens

### <a name="encrypted-create"></a> How to create an encrypted JWK using a symmetric (secret) key

```java
/**
 * Create a JWT claims set object. Please refer to RFC 7519 § 4.1. Registered Claim Names for details
 * about each claim.
 *
 * Note the use of chained setters.
 */
JwtClaims joseClaims = new JwtClaims()
    .setIssuer("Issuer")
    .setAudience("Audience")
    .setExpirationTime(Instant.now().plus(2, ChronoUnit.HOURS))
    .setNotBefore(Instant.now().minus(1, ChronoUnit.MINUTES))
    .setIssuedAt(Instant.now())
    .setJwtId(UUID.randomUUID().toString())
    .setSubject("Subject")
    .addClaim("domain", "somedomain.com")
    .addClaim("email", "someone@somedomain.com");

/**
 * Convert the JWT Claims objects to JSON
 */
String joseClaimsJson = joseClaims.toJson();

System.out.println("Claims:");
System.out.println(joseClaimsJson);
System.out.println();

/**
 * Generate random secret key
 */
byte[] secret = new byte[32];
SecureRandom secureRandom = new SecureRandom();
secureRandom.nextBytes(secret);

/**
 * Create a JSON Web Signature with the serialized JWT Claims as payload.
 */
JsonWebEncryption jwe = JweBuilder.getInstance()
    .withStringPayload(joseClaimsJson)
    .buildJweJsonFlattened(Base64Utility.toBase64Url(secret));
String jwt = jwe.toCompactForm();
System.out.println("JWT:");
System.out.println(jwt);
System.out.println();
```

### <a name="encrypted-consume"></a> How to consume an encrypted JWK using a symmetric (secret) key

```java
/**
 * Consume the JWT
 */
JwtReader jwtDecoded = JwtReader.readCompactForm(jwt);
/**
 * In this instance we have a JWE.
 */
assertEquals(JwtReader.Type.Encrypted, jwtDecoded.getType());
JsonWebEncryption jweDecoded = jwtDecoded.getJsonWebEncryption();

String plaintext = JweDecryptor.createFor(jweDecoded)
    .decrypt(secret)
    .getAsString();

System.out.println("JWT Claims as JSON: " + plaintext);
JwtClaims claims = JwtClaims.fromJson(plaintext);

System.out.println("claims.getIssuer() = " + claims.getIssuer());
System.out.println("claims.getAudience() = " + claims.getAudience());
System.out.println("claims.getSubject() = " + claims.getSubject());

assertEquals(jwe, jweDecoded);
```

### <a name="encrypted"></a> How to verify an encrypted JWK 

An encrypted JWT is implicitly validated during decryption. Unsuccessful decryption means that either an incorrect decryption key has been used or that the encrypted message has been tampered with and is invalid.