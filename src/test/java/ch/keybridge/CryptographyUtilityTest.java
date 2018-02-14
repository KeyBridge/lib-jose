package ch.keybridge;

import ch.keybridge.jose.jwe.keymgmt.EKeyManagementAlgorithm;
import ch.keybridge.jose.jwk.JwkRsaPrivateKey;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.jose.util.JsonMarshaller;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;

public class CryptographyUtilityTest {
  @Test
  public void encryptAndDecrypt() throws Exception {
    final String jwkJson = TestFileReader.getTestCase("/rfc7516/appendix-a/rsa-private-key.json");

    JwkRsaPrivateKey key = JsonMarshaller.fromJson(jwkJson, JwkRsaPrivateKey.class);

    String algorithm = EKeyManagementAlgorithm.RSA_OAEP.getJavaAlgorithm();

    byte[] plaintext = "some text for testing".getBytes(StandardCharsets.UTF_8);
    byte[] cipher = CryptographyUtility.encrypt(plaintext, key.getPublicKey(), algorithm);

    byte[] decrypted = CryptographyUtility.decrypt(cipher, key.getPrivateKey(), algorithm);
    assertArrayEquals(plaintext, decrypted);
  }

}