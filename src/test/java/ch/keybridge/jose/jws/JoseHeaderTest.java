package ch.keybridge.jose.jws;

import ch.keybridge.jose.JoseHeader;
import ch.keybridge.TestFileReader;
import ch.keybridge.jose.io.JsonUtility;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;

import static org.junit.Assert.assertEquals;

public class JoseHeaderTest {
  private JsonUtility<JoseHeader> readerWriter;
  @Before
  public void setUp() throws Exception {
    readerWriter = new JsonUtility<>(JoseHeader.class);
  }

  @Test
  public void critFieldTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7515/section4-jose-header/jose-header-crit-field-example.json");
    JoseHeader header = readerWriter.fromJson(json);
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