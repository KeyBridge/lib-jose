package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

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
  public void printKeysAsJwk() throws IOException {
    RsaPrivateJwk jwkPrivateKey = RsaPrivateJwk.getInstance(keyPair, keyId);
    System.out.println("Private key:");
    System.out.println(JsonMarshaller.toJson(jwkPrivateKey));
    System.out.println();

    RsaPublicJwk jwkPublicKey = RsaPublicJwk.getInstance((RSAPublicKey) keyPair.getPublic());
    System.out.println("Public key:");
    System.out.println(JsonMarshaller.toJson(jwkPublicKey));
    System.out.println();
  }

  @Test
  public void createConsumeAndValidateExample() throws Exception {

    /**
     * Create a JSON Web Signature with a string as payload
     */
    JwsBuilder.Signable jwsBuilder = JwsBuilder.getInstance()
        .withStringPayload("hi")
        // sign it with our private key and specify a random UUID as the key ID
        .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId);
    String jwsJsonGeneral = jwsBuilder.buildJsonWebSignature().toJson();
    String jwsCompact = jwsBuilder.buildCompact();

    System.out.println("JWS JSON general:\n" + JsonMarshaller.toJsonPrettyFormatted(jwsBuilder.buildJsonWebSignature
        ()));
    System.out.println();
//    System.out.println("JWS compact form:\n" + jwsCompact);
//    System.out.println();


    System.out.println("jwsJsonGeneral = " + jwsJsonGeneral);

    /**
     * Consume the JWS
     */
    // From compact form
//    GeneralJsonSignature decodedFromCompactForm = GeneralJsonSignature.fromCompactForm(jwsCompact);
    // From JSON General form
    JsonWebSignature decodedFromJsonGeneral = JsonWebSignature.fromJson(jwsJsonGeneral);

//    assertEquals(jwsBuilder.buildJsonWebSignature(), decodedFromCompactForm);
//    assertEquals(jwsBuilder.buildJsonWebSignature(), decodedFromJsonGeneral);

    /**
     * Validate the JWT
     */
//    boolean isValid = SignatureValidator.isValid(decodedFromCompactForm.getSignatures().get(0), keyPair.getPublic());
//    assertTrue(isValid);
//    System.out.println("JWS is valid: " + isValid);
  }

}
