package org.ietf;

import org.ietf.jose.jwa.JWEKeyAlgorithmType;
import org.ietf.jose.jwk.RsaPrivateKey;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;

public class CryptographyUtilityTest {
  @Test
  public void encryptAndDecrypt() throws Exception {
    final String jwkJson = TestFileReader.getTestCase("/rfc7516/appendix-a/rsa-private-key.json");

    RsaPrivateKey key = JsonMarshaller.fromJson(jwkJson, RsaPrivateKey.class);

    String algorithm = JWEKeyAlgorithmType.RSA_OAEP.getJavaAlgorithm();

    byte[] plaintext = "some text for testing".getBytes(StandardCharsets.UTF_8);
    byte[] cipher = CryptographyUtility.encrypt(plaintext, key.getPublicKey(), algorithm);

    byte[] decrypted = CryptographyUtility.decrypt(cipher, key.getPrivateKey(), algorithm);
    assertArrayEquals(plaintext, decrypted);
  }

}