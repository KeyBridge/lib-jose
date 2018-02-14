package ch.keybridge.jose.jws;

import ch.keybridge.TestUtil;
import ch.keybridge.jose.JoseCryptoHeader;
import ch.keybridge.jose.jwk.JsonWebKey;
import ch.keybridge.jose.jwk.JwkRsaPrivateKey;
import ch.keybridge.jose.util.Base64Utility;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static ch.keybridge.TestUtil.createRandomString;
import static ch.keybridge.jose.jws.ESignatureAlgorithm.*;
import static java.util.Arrays.asList;
import static junit.framework.TestCase.*;

public class JwsJsonSignatureTest {
  private static void testSingAndVerifyRSA(byte[] payload, PublicKey publicKey, PrivateKey privateKey,
                                           ESignatureAlgorithm alg,
                                           List<PublicKey> wrongPublicKeys) {
    try {
      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      JwsJson jws = new JwsBuilder().withPayload(payload).sign(privateKey, alg).buildJson();
      JwsSignature signature = jws.getSignatures().get(0); //JwsSignature.getInstance(payload, privateKey, header);
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

  private static void testSingAndVerifySymmetric(byte[] payload, String secret, ESignatureAlgorithm alg) {
    try {
      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      JwsJson jws = new JwsBuilder().withPayload(payload).sign(secret, alg).buildJson();
      JwsSignature signature = jws.getSignatures().get(0); //JwsSignature.getInstance(payload, privateKey, header);
      assertTrue(signature.isValidSignature(payload, secret));

      for (int i = 0; i < 100; i++) {
        assertFalse(signature.isValidSignature(payload, TestUtil.getAlteredString(secret)));
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
    JsonWebKey keyOne = JwkRsaPrivateKey.getInstance(keyPair);
    JsonWebKey keyTwo = JwkRsaPrivateKey.getInstance(keyPair);

    keyOne.setAlg(RS256.getJoseAlgorithmName());
    keyTwo.setAlg(RS512.getJoseAlgorithmName());

    JwsSignature signature = JwsSignature.getInstance("sign this".getBytes(), keyOne);
    JwsSignature signature2 = JwsSignature.getInstance("sign this".getBytes(), keyTwo);

    System.out.println(Base64Utility.toBase64Url(signature.getSignature()));
    System.out.println(Base64Utility.toBase64Url(signature2.getSignature()));

    String longString = createRandomString(10000);
    JwsSignature signature3 = JwsSignature.getInstance(longString.getBytes(), keyTwo);
    System.out.println(Base64Utility.toBase64Url(signature3.getSignature()));
  }

  @Test
  public void testRsaSignatures() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    final byte[] payload = "sign this".getBytes();

    List<PublicKey> wrongPublicKeys = IntStream.range(0, 5)
        .mapToObj(i -> generator.generateKeyPair().getPublic()).collect(Collectors.toList());
    for (ESignatureAlgorithm algorithm : asList(PS256, PS384, PS384, RS256, RS384, RS512)) {
      System.out.println(algorithm.getJoseAlgorithmName());
      testSingAndVerifyRSA(payload, keyPair.getPublic(), keyPair.getPrivate(), algorithm, wrongPublicKeys);
    }
  }

  @Test
  public void testEllipticCurveSignatures() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    /**
     * Developer note: maximum number of bits for the key is 571. Otherwise, the following is thrown:
     * java.security.InvalidParameterException: Key size must be at most 571 bits
     */
    generator.initialize(571);
    KeyPair keyPair = generator.generateKeyPair();
    final byte[] payload = "sign this".getBytes();

    List<PublicKey> wrongPublicKeys = IntStream.range(0, 5)
        .mapToObj(i -> generator.generateKeyPair().getPublic()).collect(Collectors.toList());
    for (ESignatureAlgorithm algorithm : asList(ES256, ES284, ES512)) {
      System.out.println(algorithm.getJoseAlgorithmName());
      testSingAndVerifyRSA(payload, keyPair.getPublic(), keyPair.getPrivate(), algorithm, wrongPublicKeys);
    }
  }

  @Test
  public void testHmacSignatures() {

    final byte[] payload = "sign this".getBytes();
    for (ESignatureAlgorithm algorithm : asList(HS256, HS384, HS512)) {
      System.out.println(algorithm.getJoseAlgorithmName());
      testSingAndVerifySymmetric(payload, createRandomString(20), algorithm);
    }
  }
}