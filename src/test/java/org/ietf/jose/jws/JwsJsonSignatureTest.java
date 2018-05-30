package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwkType;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwk.JWK;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.util.Base64Utility;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.Arrays.asList;
import static org.ietf.TestUtil.createRandomString;
import static org.ietf.TestUtil.getAlteredBytes;
import static org.ietf.jose.jwa.JwsAlgorithmType.*;
import static org.ietf.jose.util.Base64Utility.fromBase64Url;
import static org.ietf.jose.util.Base64Utility.toBase64Url;
import static org.junit.Assert.*;

public class JwsJsonSignatureTest {

  private static void testSignAndVerify(byte[] payload, PublicKey publicKey, PrivateKey privateKey,
                                        JwsAlgorithmType alg,
                                        List<PublicKey> wrongPublicKeys) {
    try {
      JwsHeader header = new JwsHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      GeneralJsonSignature jws = JwsBuilder.getInstance()
          .withBinaryPayload(payload)
          .sign(privateKey, alg, UUID.randomUUID().toString())
          .buildJsonGeneral();
      assertEquals(1, jws.getSignatures().size());
      Signature signature = jws.getSignatures().get(0);
      assertTrue(SignatureValidator.isValid(signature, payload, publicKey));
      wrongPublicKeys.forEach(key -> {
        try {
          assertFalse(SignatureValidator.isValid(signature, payload, key));
        } catch (Exception e) {
          e.printStackTrace();
          fail(e.getMessage());
        }
      });
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }

  private static void testSingAndVerifySymmetric(byte[] payload, String secret, JwsAlgorithmType alg) {
    try {
      JwsHeader header = new JwsHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      GeneralJsonSignature jws = JwsBuilder.getInstance()
          .withBinaryPayload(payload)
          .sign(secret, alg, UUID.randomUUID().toString())
          .buildJsonGeneral();
      assertEquals(1, jws.getSignatures().size());
      Signature signature = jws.getSignatures().get(0);
      assertTrue(SignatureValidator.isValid(signature, jws.getPayload(), secret));

      for (int i = 0; i < 100; i++) {
        String base64UrlEncodedWrongKey = toBase64Url(getAlteredBytes(fromBase64Url(secret)));
        assertFalse(SignatureValidator.isValid(signature, jws.getPayload(), base64UrlEncodedWrongKey));
      }

    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }

  @Test
  public void getInstance() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    JWK jwkOne = RsaPrivateJwk.getInstance(keyPair, UUID.randomUUID().toString());
    JWK jwkTwo = RsaPrivateJwk.getInstance(keyPair, UUID.randomUUID().toString());

    jwkOne.setJwsAlgorithmType(RS256);
    jwkTwo.setJwsAlgorithmType(RS512);

    Signature signature = Signature.getInstance("sign this".getBytes(), jwkOne);
    Signature signature2 = Signature.getInstance("sign this".getBytes(), jwkTwo);

    System.out.println(toBase64Url(signature.getSignatureBytes()));
    System.out.println(toBase64Url(signature2.getSignatureBytes()));

    String longString = createRandomString(10000);
    Signature signature3 = Signature.getInstance(longString.getBytes(), jwkTwo);
    System.out.println(toBase64Url(signature3.getSignatureBytes()));
  }

  @Test
  public void testRsaSignatures() throws Exception {
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance(JwkType.RSA.name());
    rsaGenerator.initialize(2048);
    KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
    final byte[] payload = "sign this".getBytes();

    List<PublicKey> wrongPublicKeys = IntStream.range(0, 5)
      .mapToObj(i -> rsaGenerator.generateKeyPair().getPublic()).collect(Collectors.toList());

    for (JwsAlgorithmType algorithm : asList(RS256, RS384, RS512)) {
      System.out.println("  testSignAndVerify RSA " + algorithm.getJoseAlgorithmName());
      testSignAndVerify(payload, rsaKeyPair.getPublic(), rsaKeyPair.getPrivate(), algorithm, wrongPublicKeys);
    }
  }

  @Test
  public void testEllipticCurveSignatures() throws Exception {
    KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance(JwkType.EC.name());
    /**
     * Developer note: maximum number of bits for the key is 571. Otherwise, the
     * following is thrown: java.security.InvalidParameterException: Key size
     * must be at most 571 bits
     */
    ecGenerator.initialize(571);
    KeyPair keyPair = ecGenerator.generateKeyPair();
    final byte[] payload = "sign this".getBytes();

    List<PublicKey> wrongPublicKeys = IntStream.range(0, 5)
      .mapToObj(i -> ecGenerator.generateKeyPair().getPublic()).collect(Collectors.toList());
    for (JwsAlgorithmType algorithm : asList(ES256, ES384, ES512)) {
      System.out.println("  testSignAndVerify EC " + algorithm.getJoseAlgorithmName());
      testSignAndVerify(payload, keyPair.getPublic(), keyPair.getPrivate(), algorithm, wrongPublicKeys);
    }
  }

  @Test
  public void testHmacSignatures() {
    final byte[] payload = "sign this".getBytes();
    for (JwsAlgorithmType algorithm : asList(HS256, HS384, HS512)) {
      System.out.println("  testSignAndVerify HMAC " + algorithm.getJoseAlgorithmName());
      testSingAndVerifySymmetric(payload, toBase64Url(createRandomString(20)), algorithm);
    }
  }

  @Test
  public void testSignatureFromBuilder() throws Exception {
    final String payload = "payload";
    final String secret = Base64Utility.toBase64Url(KeyGenerator.getInstance("HmacSHA256").generateKey().getEncoded());

    FlattenedJsonSignature jws = JwsBuilder.getInstance()
      .withStringPayload(payload)
        .sign(secret, JwsAlgorithmType.HS256, UUID.randomUUID().toString())
      .buildJsonFlattened();

    assertTrue(SignatureValidator.isValid(jws, secret));
  }
}
