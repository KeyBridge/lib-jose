package ch.keybridge.jose.jws;

import ch.keybridge.jose.util.EncodingUtility;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.TestFileReader;
import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.io.JsonUtility;
import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.jwk.JwkRsaKey;
import org.junit.Test;

import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;

import static org.junit.Assert.assertEquals;

public class JwsExamplesTest {

  private static final Charset UTF8 = Charset.forName("UTF-8");

  private static byte[] convertToSignedBytes(int[] unsignedBytes) {
    byte[] bytes = new byte[unsignedBytes.length];
    for (int i = 0; i < unsignedBytes.length; i++) {
      final int value = unsignedBytes[i];
      bytes[i] = (byte) (value < 128 ? value : value - 256);
    }
    return bytes;
  }

  @Test
  public void encodingTest() throws Exception {
    String payload = "It\u2019s a dangerous business, Frodo, going out your " +
    "door. You step onto the road, and if you don't keep your feet, " +
    "there\u2019s no knowing where you might be swept off " +
    "to.";
    assertEquals
        ("SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
        EncodingUtility.encodeBase64Url(payload));

    final String fullPayload = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9" +
        '.' + EncodingUtility.encodeBase64Url(payload);



    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    JwkRsaKey key = (JwkRsaKey)new JsonUtility<>(JWK.class).fromJson(json);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKeySpec spec = new RSAPrivateKeySpec(key.getModulus(), key.getPrivateExponent());
    PrivateKey pk = kf.generatePrivate(spec);
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(pk);
    signer.update(fullPayload.getBytes(UTF8));
    byte[] signatureBytes = signer.sign();
    final String expectedSignature = "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";
    assertEquals(expectedSignature, EncodingUtility.encodeBase64Url(signatureBytes));
    /**
     * Check whether the EncryptionUtility returns the same result
     */
    byte[] signatureUtility = CryptographyUtility.sign(fullPayload.getBytes(UTF8), key, ESignatureAlgorithm.RS256);
    assertEquals(expectedSignature, EncodingUtility.encodeBase64Url(signatureUtility));
  }

}