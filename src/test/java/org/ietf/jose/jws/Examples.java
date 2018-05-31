package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
  public void createConsumeAndValidateExample() throws Exception {

    /**
     * Create a JSON Web Signature with a string as payload
     */
    JwsBuilder jwsBuilder = JwsBuilder.getInstance()
        .withStringPayload("hi")
        // sign it with our private key and specify a random UUID as the key ID
        .sign(keyPair.getPrivate(), JwsAlgorithmType.RS256, keyId);
    String jwsJsonGeneral = jwsBuilder.buildJsonGeneral().toJson();
    String jwsCompact = jwsBuilder.buildCompact();

    System.out.println("JWS JSON general:\n" + JsonMarshaller.toJsonPrettyFormatted(jwsBuilder.buildJsonGeneral()));
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
    GeneralJsonSignature decodedFromJsonGeneral = GeneralJsonSignature.fromJson(jwsJsonGeneral);

//    assertEquals(jwsBuilder.buildJsonGeneral(), decodedFromCompactForm);
//    assertEquals(jwsBuilder.buildJsonGeneral(), decodedFromJsonGeneral);

    /**
     * Validate the JWT
     */
//    boolean isValid = SignatureValidator.isValid(decodedFromCompactForm.getSignatures().get(0), keyPair.getPublic());
//    assertTrue(isValid);
//    System.out.println("JWS is valid: " + isValid);
  }

  @Test
  public void name() throws IOException {
    String json = "{\"payload\":\"aGk\",\"protected\":{\"alg\":\"RS256\"," +
        "\"kid\":\"82bcb607-15ff-4e54-aea8-1843c596de4f\"}," +
        "\"signature\":\"EV9OHcLaK5_ZMqGa5Jhvd2orcBbp9dU7D4Z6Qhj5QugE4XJ6UaRiOPfGqSDRgfU" +
        "-e2dknFQzmRZyydXuzWHhsN_UnWjNiTSniWGOmbviH17fCh-s19hkAiGiCH7WsPI_ZZe3eDj_9tPbogRvM8XfwcSt_Nur32" +
        "-sC8emtU0wIsVQyk8v_pQq-PRjoz4tbgM9BsWYFXXwbiH9ki61M0v5CPyA_i1fwXO_PCtz9k9X" +
        "-LJYaDRJRxgOzX_G3P2dVcGVPPEiJAoOZyTZ0eqEw8jQikf0Sks6nv_459YgqCoPfK6aD0w7cQzud" +
        "-cA6JmZTw4lpYSuwSYEAk11frnOGO00fg\"}";
    String json2 = "{\"payload\":\"aGk\",\"protected\":{\"kid\":\"82bcb607-15ff-4e54-aea8-1843c596de4f\"," +
        "\"alg\":\"RS256\"}," +
        "\"signature\":\"EV9OHcLaK5_ZMqGa5Jhvd2orcBbp9dU7D4Z6Qhj5QugE4XJ6UaRiOPfGqSDRgfU" +
        "-e2dknFQzmRZyydXuzWHhsN_UnWjNiTSniWGOmbviH17fCh-s19hkAiGiCH7WsPI_ZZe3eDj_9tPbogRvM8XfwcSt_Nur32" +
        "-sC8emtU0wIsVQyk8v_pQq-PRjoz4tbgM9BsWYFXXwbiH9ki61M0v5CPyA_i1fwXO_PCtz9k9X" +
        "-LJYaDRJRxgOzX_G3P2dVcGVPPEiJAoOZyTZ0eqEw8jQikf0Sks6nv_459YgqCoPfK6aD0w7cQzud" +
        "-cA6JmZTw4lpYSuwSYEAk11frnOGO00fg\"}";
    GeneralJsonSignature.fromJson(json);
    GeneralJsonSignature.fromJson(json2);
  }
}
