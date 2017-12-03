package ch.keybridge.jose.io;

import ch.keybridge.jose.jwe.JWE;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static ch.keybridge.jose.util.JsonMarshaller.fromJson;
import static ch.keybridge.jose.util.JsonMarshaller.toJson;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/12/2017
 */
public class JsonMarshallerTest {

  @Test
  public void jsonMarshallUnmarshall() {
    try {
      KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
      JWE original = JWE.getInstance("somePayload".getBytes(StandardCharsets.UTF_8), keyPair.getPublic());
      JWE unmarshalled = fromJson(toJson(original, JWE.class), JWE.class);
      assertEquals(original, unmarshalled);
    } catch (Exception e) {
      fail("Unexpected exception thrown in test");
      e.printStackTrace();
    }
  }
}