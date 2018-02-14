package ch.keybridge.jose.io;

import ch.keybridge.jose.jwe.JweJsonFlattened;
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
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair keyPair = generator.generateKeyPair();
      JweJsonFlattened original = JweJsonFlattened.getInstance("somePayload".getBytes(StandardCharsets.UTF_8),
          keyPair.getPublic());
      JweJsonFlattened unmarshalled = fromJson(toJson(original), JweJsonFlattened.class);
      assertEquals(original, unmarshalled);
    } catch (Exception e) {
      e.printStackTrace();
      fail("Unexpected exception thrown in test");
    }
  }
}