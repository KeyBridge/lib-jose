/*
 * Copyright 2020 Key Bridge. All rights reserved. Use is subject to license
 * terms.
 *
 * This software code is protected by Copyrights and remains the property of
 * Key Bridge and its suppliers, if any. Key Bridge reserves all rights in and to
 * Copyrights and no license is granted under Copyrights in this Software
 * License Agreement.
 *
 * Key Bridge generally licenses Copyrights for commercialization pursuant to
 * the terms of either a Standard Software Source Code License Agreement or a
 * Standard Product License Agreement. A copy of either Agreement can be
 * obtained upon request by sending an email to info@keybridgewireless.com.
 *
 * All information contained herein is the property of Key Bridge and its
 * suppliers, if any. The intellectual and technical concepts contained herein
 * are proprietary.
 */
package org.ietf.jose.jwt;

import com.thedeanda.lorem.LoremIpsum;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Key Bridge
 */
public class SimpleJwtTest {

  private LoremIpsum l = LoremIpsum.getInstance();

  private KeyPair keyPair;
  private String keyId = UUID.randomUUID().toString();

  @Before
  public void generateKeyPair() throws NoSuchAlgorithmException {
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
  }

  @Test
  public void testMethod() throws IOException, GeneralSecurityException, Exception {

    String uid = UUID.randomUUID().toString();
//    String secret = UUID.randomUUID().toString();

    JwtClaims joseClaims = new JwtClaims()
      .withIssuer(uid)
      .withSubject(uid)
      .withAudience(l.getUrl())
      .withDuration(Duration.ofSeconds(3600));

    /**
     * Convert the JWT Claims objects to JSON
     */
    String joseClaimsJson = joseClaims.toJson(); // throws IOException

    /**
     * Create a JSON Web Signature with the serialized JWT Claims as payload.
     */
    JwsBuilder.Signable jwsBuilder = JwsBuilder.getInstance()
      .withStringPayload(joseClaimsJson)
      .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId); // throws GeneralSecurityException

    String jwt = jwsBuilder.build();
    System.out.println("JWT:");
    System.out.println(jwt);
    System.out.println(jwt.length() + " chars ");

    /**
     * Consume the JWT
     */
    JwtReader jwtDecoded = JwtReader.read(jwt);

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
    JwtClaims claims = JwtClaims.fromJson(payload); // throws Exception

    System.out.println("  claims " + claims.getClaims());

    /**
     * Validate the JWT by using the SignatureValidator class
     */
    boolean isValid = SignatureValidator.isValid(decodedFromCompactForm.getSignatures().get(0), keyPair.getPublic());
    System.out.println(" valid signature " + isValid);

  }

  @Test
  public void createConsumeAndValidateSignedExample() throws NoSuchAlgorithmException, IOException, GeneralSecurityException, Exception {

    /**
     * Create a JWT claims set object. Please refer to RFC 7519 § 4.1.
     * Registered Claim Names for details about each claim.
     * <p>
     * The following fields are automatically set in the JwtClaims constructor:
     * [jwtid, issuedAt, notBefore]
     * <p>
     * If the issuer is key bridge the `scope` claim will be set. If you are
     * issuing your own JWT do not include a scope claim; it will ignored.
     */
    JwtClaims jwtClaims = new JwtClaims()
      .withIssuer("issuer is Key Bridge URL")
      .withSubject("subject is the user Consumer key")
      .withAudience("audience is key bridge URL")
      .withDuration(Duration.ofDays(7)) // sets the expiration
      .withClaim(ClaimType.scope, Arrays.asList("scope-1", "scope-2", "scope-3")); // key bridge only
    /**
     * Retrieve the subject's shared secret
     */
    String consumerKey = UUID.randomUUID().toString();
    System.out.println("debug consumerKey = " + consumerKey);

    SecretKey key = SecretKeyBuilder.fromSharedSecret(consumerKey); // throws NoSuchAlgorithmException
    String keyId = "keyId";

    String jwt = JwsBuilder.getInstance()
      .withClaimsPayload(jwtClaims)
      .withKey(key, keyId)
      .build();

    System.out.println("JWS = " + jwt);

//      .sign(key, JwsAlgorithmType.RS256, keyId) // throws IOException, GeneralSecurityException
//      .buildJsonWebSignature()
//      .toCompactForm();
    /**
     * Consume the JWT
     */
    JsonWebSignature jws = JwtReader.read(jwt).getJsonWebSignature();

    JwtClaims claims = jws.getClaims(); // throws Exception
//    boolean isValid = SignatureValidator.isValid(jws.getSignatures(), key);

  }

}
