package ch.keybridge;

import ch.keybridge.jose.algorithm.EKeyManagementAlgorithm;
import ch.keybridge.jose.io.JsonUtility;
import ch.keybridge.jose.util.EncodingUtility;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.jose.jwk.JwkRsaKey;
import org.junit.Test;

import static org.junit.Assert.*;

public class CryptographyUtilityTest {
  @Test
  public void encrypt() throws Exception {
    final String jwkJson = TestFileReader.getTestCase("/rfc7516/appendix-a/rsa-private-key.json");

    JsonUtility<JwkRsaKey> jwkMarshaller = new JsonUtility<>(JwkRsaKey.class, true);
    JwkRsaKey key = jwkMarshaller.fromJson(jwkJson);

    String algorithm = EKeyManagementAlgorithm.RSA_OAEP.getJavaAlgorithm();

    byte[] plaintext = EncodingUtility.getUtf8Bytes("some text for testing");
    byte[] cipher = CryptographyUtility.encrypt(plaintext, key.getPublicKey(), algorithm);

    byte[] decrypted = CryptographyUtility.decrypt(cipher, key.getPrivateKey(), algorithm);
    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void decrypt() throws Exception {
  }

  @Test
  public void encode() throws Exception {
  }

}