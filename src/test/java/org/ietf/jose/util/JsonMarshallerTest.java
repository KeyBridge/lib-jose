package org.ietf.jose.util;

import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweJsonFlattened;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.ietf.jose.util.JsonMarshaller.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/12/2017
 */
public class JsonMarshallerTest {

  @Test
  public void jsonMarshalUnmarshal() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair keyPair = generator.generateKeyPair();
      JweJsonFlattened original = JweBuilder.getInstance()
          .withBinaryPayload("somePayload".getBytes(StandardCharsets.UTF_8))
          .buildJweJsonFlattened(keyPair.getPublic());

      JweJsonFlattened unmarshalled = fromJson(toJson(original), JweJsonFlattened.class);
      String jsonPretty = toJsonPrettyFormatted(original);
      System.out.println(jsonPretty);
      JweJsonFlattened unmarshalledFromPrettyJson = fromJson(jsonPretty, JweJsonFlattened.class);
      assertEquals(original, unmarshalled);
      assertEquals(original, unmarshalledFromPrettyJson);
    } catch (Exception e) {
      e.printStackTrace();
      fail("Unexpected exception thrown in test");
    }
  }
}