# JSON Web Token (JWT) Code Examples

## How to create a signed JWT

```java
    /**
     * Create a JWT claims set object. Please refer to RFC 7519 § 4.1. Registered Claim Names for details
     * about each claim.
     */
    JwtClaims joseClaims = new JwtClaims();
    joseClaims.setIssuer("Issuer");
    joseClaims.setAudience("Audience");
    // Set the expiration time of this JWT to be two hours from now
    joseClaims.setExpirationTime(Instant.now().plus(2, ChronoUnit.HOURS));
    // A JWT must be processed on or after the Not Before values. Let's set this to one minute from now
    joseClaims.setNotBefore(Instant.now().minus(1, ChronoUnit.MINUTES));
    joseClaims.setIssuedAt(Instant.now());
    /**
     * The JWT ID is used a nonce to prevent replay attacks. It is recommended to use a random UUID
     */
    joseClaims.setJwtId(UUID.randomUUID().toString());
    joseClaims.setSubject("Subject");

    /**
     * Convert the JWT Claims objects to JSON
     */
    String joseClaimsJson = JsonMarshaller.toJson(joseClaims);

    System.out.println("Claims:");
    System.out.println(joseClaimsJson);
    System.out.println();

    /**
     * Create a JSON Web Signature with the serialized JWT Claims as payload.
     */
    JwsBuilder jwsBuilder = JwsBuilder.getInstance()
        .withStringPayload(joseClaimsJson)
        // sign it with our private key and specify a random UUID as the key ID
        .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId);
    String jwt = jwsBuilder.buildCompact();
    System.out.println("JWT:");
    System.out.println(jwt);
    System.out.println();
```

## How to consume a signed JWT

```java
    FlattendedJsonSignature decodedFromCompactForm = FlattendedJsonSignature.fromCompactForm(jwt);
    String payload = decodedFromCompactForm.getStringPayload();
    System.out.println("JWT Claims as JSON: " + payload);
    JwtClaims claims = JsonMarshaller.fromJson(payload, JwtClaims.class);

    System.out.println("claims.getIssuer() = " + claims.getIssuer());
    System.out.println("claims.getAudience() = " + claims.getAudience());
    System.out.println("claims.getSubject() = " + claims.getSubject());
```

## How to validate a signed JWT

```java
    boolean isValid = SignatureValidator.isValid(decodedFromCompactForm, keyPair.getPublic());
    assertTrue(isValid);
```