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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.UUID;
import org.ietf.jose.jwa.JwsAlgorithmType;
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

  private KeyPair keyPair;
  private String keyId = UUID.randomUUID().toString();

  @Before
  public void generateKeyPair() throws NoSuchAlgorithmException {
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
  }

  @Test
  public void testMethod() throws IOException, GeneralSecurityException, Exception {

    String key = "8640a868-dedd-427c-8d6a-2116ee2976c3";
    String secret = "ddb8ff562cb4e3557cffb767d63ab35122865662465f8e7d78d4f55c90c48a82";

    JwtClaims joseClaims = new JwtClaims()
      .withIssuer("8640a868-dedd-427c-8d6a-2116ee2976c3")
      .withSubject("8640a868-dedd-427c-8d6a-2116ee2976c3")
      .withAudience("https://keybridgewireless.com")
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

    String jwt = jwsBuilder.buildCompact();
    System.out.println("JWT:");
    System.out.println(jwt);
    System.out.println(jwt.length() + " chars ");

    /**
     * Consume the JWT
     */
    JwtReader jwtDecoded = JwtReader.readCompactForm(jwt);

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

}
