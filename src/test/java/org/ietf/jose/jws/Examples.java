package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
  public void createConsumeAndValidateExample() throws Exception {

    /**
     * Create a JSON Web Signature with a string as payload
     */
    JwsBuilder jwsBuilder = JwsBuilder.getInstance()
        .withStringPayload("hi")
        // sign it with our private key and specify a random UUID as the key ID
        .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId);
    String jwsJsonFlattened = jwsBuilder.buildJsonFlattened().toJson();
    String jwsJsonGeneral = jwsBuilder.buildJsonGeneral().toJson();
    String jwsCompact = jwsBuilder.buildCompact();

    System.out.println("JWS JSON flattened:\n" + JsonMarshaller.toJsonPrettyFormatted(jwsBuilder.buildJsonFlattened()));
    System.out.println();
    System.out.println("JWS JSON general:\n" + JsonMarshaller.toJsonPrettyFormatted(jwsBuilder.buildJsonGeneral()));
    System.out.println();
    System.out.println("JWS compact form:\n" + jwsCompact);
    System.out.println();

    /**
     * Consume the JWS
     */
    // From compact form
    FlattenedJsonSignature decodedFromCompactForm = FlattenedJsonSignature.fromCompactForm(jwsCompact);
    // From JSON Flattened form
    FlattenedJsonSignature decodedFromJsonFlattened = FlattenedJsonSignature.fromJson(jwsJsonFlattened);
    // From JSON General form
    GeneralJsonSignature decodedFromJsonGeneral = GeneralJsonSignature.fromJson(jwsJsonGeneral);

    assertEquals(jwsBuilder.buildJsonFlattened(), decodedFromCompactForm);
    assertEquals(jwsBuilder.buildJsonFlattened(), decodedFromJsonFlattened);
    assertEquals(jwsBuilder.buildJsonFlattened(), decodedFromJsonGeneral.toFlattened());

    /**
     * Validate the JWT
     */
    boolean isValid = SignatureValidator.isValid(decodedFromCompactForm, keyPair.getPublic());
    assertTrue(isValid);
    System.out.println("JWS is valid: " + isValid);
  }
}
