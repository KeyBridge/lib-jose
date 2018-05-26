package org.ietf.jose.jws;

import org.ietf.TestFileReader;
import org.ietf.jose.JoseCryptoHeader;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class JoseHeaderTest {

  @Test
  public void critFieldTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7515/section4-jose-header/jose-header-crit-field-example.json");
    JoseCryptoHeader header = JsonMarshaller.fromJson(json, JoseCryptoHeader.class);
    /**
     * {
     *  "alg":"ES256",
     *  "crit":["exp"],
     *  "exp":1363284000
     * }
     */
    assertEquals("ES256", header.getAlg());
    assertEquals(1, header.getCrit().size());
    assertEquals("exp", header.getCrit().get(0));
    /**
     * Developer note:
     * The extra field 'exp', listed in the 'crit' list is not supported by the implementation,
     * therefore this object should be discarded.
     */
  }

}