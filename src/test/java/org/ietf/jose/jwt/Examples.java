package org.ietf.jose.jwt;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweDecryptor;
import org.ietf.jose.jwe.JweJsonFlattened;
import org.ietf.jose.jws.GeneralJsonSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.util.Base64Utility;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class Examples {

  private KeyPair keyPair;
  private String keyId = UUID.randomUUID().toString();

  @Before
  public void generateKeyPair() throws NoSuchAlgorithmException {
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
  }

  @Test
  public void createConsumeAndValidateSignedExample() throws Exception {
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
    GeneralJsonSignature decodedFromCompactForm = jwtDecoded.getJwsFlattenedObject();
    /**
     * Get the payload as string:
     */
    String payload = decodedFromCompactForm.getStringPayload();
    System.out.println("JWT Claims as JSON: " + payload);
    /**
     * Deserialize the payload as a JwtClaims object
     */
    JwtClaims claims = JwtClaims.fromJson(payload);

    System.out.println("claims.getIssuer() = " + claims.getIssuer());
    System.out.println("claims.getAudience() = " + claims.getAudience());
    System.out.println("claims.getSubject() = " + claims.getSubject());

    assertEquals(jwsBuilder.buildJsonGeneral(), decodedFromCompactForm);

    /**
     * Validate the JWT by using the SignatureValidator class
     */
    boolean isValid = SignatureValidator.isValid(decodedFromCompactForm.getSignatures().get(0), keyPair.getPublic());
    assertTrue(isValid);
    System.out.println();
  }

  @Test
  public void createConsumeAndValidateEncryptedExample() throws Exception {
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
    JweJsonFlattened jwe = JweBuilder.getInstance()
        .withStringPayload(joseClaimsJson)
        .buildJweJsonFlattened(Base64Utility.toBase64Url(secret));
    String jwt = jwe.toCompactForm();
    System.out.println("JWT:");
    System.out.println(jwt);
    System.out.println();

    /**
     * Consume the JWT
     */
    JwtReader jwtDecoded = JwtReader.readCompactForm(jwt);
    /**
     * In this instance we have a JWE.
     */
    assertEquals(JwtReader.Type.Encrypted, jwtDecoded.getType());
    JweJsonFlattened jweDecoded = jwtDecoded.getJweFlattenedObject();

    String plaintext = JweDecryptor.createFor(jweDecoded)
        .decrypt(secret)
        .getAsString();

    System.out.println("JWT Claims as JSON: " + plaintext);
    JwtClaims claims = JwtClaims.fromJson(plaintext);

    System.out.println("claims.getIssuer() = " + claims.getIssuer());
    System.out.println("claims.getAudience() = " + claims.getAudience());
    System.out.println("claims.getSubject() = " + claims.getSubject());

    assertEquals(jwe, jweDecoded);

    /**
     * Validate the JWT
     *
     * An encrypted JWT is implicitly validated during decryption. Unsuccessful decryption means
     * that either an incorrect decryption key has been used or that the encrypted message has been
     * tampered with and is invalid.
     */
  }
}
