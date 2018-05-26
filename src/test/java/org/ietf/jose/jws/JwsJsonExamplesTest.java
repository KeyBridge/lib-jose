package org.ietf.jose.jws;

import org.ietf.jose.jwa.JWSAlgorithmType;
import org.ietf.TestFileReader;
import org.ietf.jose.jwk.JwkRsaPrivateKey;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;

import static org.ietf.jose.util.Base64Utility.toBase64Url;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

public class JwsJsonExamplesTest {

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
            toBase64Url(payload));

    final String fullPayload = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9" +
        '.' + toBase64Url(payload);

    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    JwkRsaPrivateKey key = JsonMarshaller.fromJson(json, JwkRsaPrivateKey.class);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKeySpec spec = new RSAPrivateKeySpec(key.getModulus(), key.getPrivateExponent());
    PrivateKey pk = kf.generatePrivate(spec);
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(pk);
    signer.update(fullPayload.getBytes(UTF_8));
    byte[] signatureBytes = signer.sign();
    final String expectedSignature = "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";
    assertEquals(expectedSignature, toBase64Url(signatureBytes));
    key.setAlg(JWSAlgorithmType.RS256.getJoseAlgorithmName());
    /**
     * Check whether the EncryptionUtility returns the same result
     */
    byte[] signatureUtility = CryptographyUtility.sign(fullPayload.getBytes(UTF_8), key);
    assertEquals(expectedSignature, toBase64Url(signatureUtility));
  }

}