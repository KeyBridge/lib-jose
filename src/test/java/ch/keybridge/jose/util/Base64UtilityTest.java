package ch.keybridge.jose.util;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/12/2017
 */
public class Base64UtilityTest {

  @Test
  public void stringTest() {
    String input = "some input string with international characters: ąčęėįšų";
    String base64Url = Base64Utility.toBase64Url(input);
    String output = Base64Utility.fromBase64UrlToString(base64Url);
    assertEquals(input, output);
  }

  @Test
  public void binaryTest() {
    byte[] input = new byte[]{0, -10, 34, 127, -128};
    String base64Url = Base64Utility.toBase64Url(input);
    byte[] output = Base64Utility.fromBase64Url(base64Url);
    assertArrayEquals(input, output);
  }
}