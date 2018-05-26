package org.ietf.jose.jws;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.crypto.KeyGenerator;
import org.ietf.jose.JoseCryptoHeader;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwk.JWK;
import org.ietf.jose.jwk.key.RsaPrivateKey;
import org.ietf.jose.util.Base64Utility;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.ietf.TestUtil.createRandomString;
import static org.ietf.TestUtil.getAlteredBytes;
import static org.ietf.jose.jwa.JwsAlgorithmType.*;
import static org.ietf.jose.util.Base64Utility.fromBase64Url;
import static org.ietf.jose.util.Base64Utility.toBase64Url;
import static org.junit.Assert.*;

public class JwsJsonSignatureTest {

  private static void testSingAndVerifyRSA(byte[] payload, PublicKey publicKey, PrivateKey privateKey,
                                           JwsAlgorithmType alg,
                                           List<PublicKey> wrongPublicKeys) {
    try {
      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      JWS jws = JwsBuilder.getInstance().withBinaryPayload(payload).sign(privateKey, alg).buildJson();
      GeneralSignature signature = jws.getSignatures().get(0); //JwsSignature.getInstance(payload, privateKey, header);
      assertTrue(signature.isValidSignature(payload, publicKey));
      wrongPublicKeys.forEach(key -> {
        try {
          assertFalse(signature.isValidSignature(payload, key));
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
      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      JWS jws = JwsBuilder.getInstance().withBinaryPayload(payload).sign(secret, alg).buildJson();
      GeneralSignature signature = jws.getSignatures().get(0); //JwsSignature.getInstance(payload, privateKey, header);
      assertTrue(signature.isValidSignature(payload, secret));

      for (int i = 0; i < 100; i++) {
        String base64UrlEncodedWrongKey = toBase64Url(getAlteredBytes(fromBase64Url(secret)));
        assertFalse(signature.isValidSignature(payload, base64UrlEncodedWrongKey));
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
    JWK keyOne = RsaPrivateKey.getInstance(keyPair);
    JWK keyTwo = RsaPrivateKey.getInstance(keyPair);

    keyOne.setAlg(RS256.getJoseAlgorithmName());
    keyTwo.setAlg(RS512.getJoseAlgorithmName());

    GeneralSignature signature = GeneralSignature.getInstance("sign this".getBytes(), keyOne);
    GeneralSignature signature2 = GeneralSignature.getInstance("sign this".getBytes(), keyTwo);

    System.out.println(toBase64Url(signature.getSignatureBytes()));
    System.out.println(toBase64Url(signature2.getSignatureBytes()));

    String longString = createRandomString(10000);
    GeneralSignature signature3 = GeneralSignature.getInstance(longString.getBytes(), keyTwo);
    System.out.println(toBase64Url(signature3.getSignatureBytes()));
  }

  @Test
  public void testRsaSignatures() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    final byte[] payload = "sign this".getBytes();

    List<PublicKey> wrongPublicKeys = IntStream.range(0, 5)
      .mapToObj(i -> generator.generateKeyPair().getPublic()).collect(Collectors.toList());
    for (JwsAlgorithmType algorithm : asList(RS256, RS384, RS512)) {
      System.out.println(algorithm.getJoseAlgorithmName());
      testSingAndVerifyRSA(payload, keyPair.getPublic(), keyPair.getPrivate(), algorithm, wrongPublicKeys);
    }
  }

  @Test
  public void testEllipticCurveSignatures() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    /**
     * Developer note: maximum number of bits for the key is 571. Otherwise, the
     * following is thrown: java.security.InvalidParameterException: Key size
     * must be at most 571 bits
     */
    generator.initialize(571);
    KeyPair keyPair = generator.generateKeyPair();
    final byte[] payload = "sign this".getBytes();

    List<PublicKey> wrongPublicKeys = IntStream.range(0, 5)
      .mapToObj(i -> generator.generateKeyPair().getPublic()).collect(Collectors.toList());
    for (JwsAlgorithmType algorithm : asList(ES256, ES384, ES512)) {
      System.out.println(algorithm.getJoseAlgorithmName());
      testSingAndVerifyRSA(payload, keyPair.getPublic(), keyPair.getPrivate(), algorithm, wrongPublicKeys);
    }
  }

  @Test
  public void testHmacSignatures() {

    final byte[] payload = "sign this".getBytes();
    for (JwsAlgorithmType algorithm : asList(HS256, HS384, HS512)) {
      System.out.println(algorithm.getJoseAlgorithmName());
      testSingAndVerifySymmetric(payload, toBase64Url(createRandomString(20)), algorithm);
    }
  }

  @Test
  public void testSignatureFromBuilder() throws Exception {
    final String payload = "payload";
    final String secret = Base64Utility.toBase64Url(KeyGenerator.getInstance("HmacSHA256").generateKey().getEncoded());

    FlattendedSignature jws = JwsBuilder.getInstance()
      .withStringPayload(payload)
      .sign(secret)
      .buildJsonFlattened();

    assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), secret));
  }
}
