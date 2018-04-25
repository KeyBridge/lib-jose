package ch.keybridge.jose.jws;

import ch.keybridge.jose.JoseCryptoHeader;
import ch.keybridge.jose.jwk.JsonWebKey;
import ch.keybridge.jose.jwk.JwkRsaPrivateKey;
import ch.keybridge.jose.util.Base64Utility;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static ch.keybridge.TestUtil.createRandomString;
import static ch.keybridge.TestUtil.getAlteredBytes;
import static ch.keybridge.jose.jws.ESignatureAlgorithm.*;
import static ch.keybridge.jose.util.Base64Utility.fromBase64Url;
import static ch.keybridge.jose.util.Base64Utility.toBase64Url;
import static java.util.Arrays.asList;
import static org.junit.Assert.*;

public class JwsJsonSignatureTest {
  private static void testSingAndVerifyRSA(byte[] payload, PublicKey publicKey, PrivateKey privateKey,
                                           ESignatureAlgorithm alg,
                                           List<PublicKey> wrongPublicKeys) {
    try {
      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setAlg(alg.getJoseAlgorithmName());
      JwsJson jws = JwsBuilder.getInstance().withBinaryPayload(payload).sign(privateKey, alg).buildJson();
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
      JwsJson jws = JwsBuilder.getInstance().withBinaryPayload(payload).sign(secret, alg).buildJson();
      JwsSignature signature = jws.getSignatures().get(0); //JwsSignature.getInstance(payload, privateKey, header);
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
    JsonWebKey keyOne = JwkRsaPrivateKey.getInstance(keyPair);
    JsonWebKey keyTwo = JwkRsaPrivateKey.getInstance(keyPair);

    keyOne.setAlg(RS256.getJoseAlgorithmName());
    keyTwo.setAlg(RS512.getJoseAlgorithmName());

    JwsSignature signature = JwsSignature.getInstance("sign this".getBytes(), keyOne);
    JwsSignature signature2 = JwsSignature.getInstance("sign this".getBytes(), keyTwo);

    System.out.println(toBase64Url(signature.getSignatureBytes()));
    System.out.println(toBase64Url(signature2.getSignatureBytes()));

    String longString = createRandomString(10000);
    JwsSignature signature3 = JwsSignature.getInstance(longString.getBytes(), keyTwo);
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
      testSingAndVerifySymmetric(payload, toBase64Url(createRandomString(20)), algorithm);
    }
  }

  @Test
  public void testSignatureFromBuilder() throws Exception {
    final String payload = "payload";
    final String secret = Base64Utility.toBase64Url(KeyGenerator.getInstance("HmacSHA256").generateKey().getEncoded());

    JwsJsonFlattened jws = JwsBuilder.getInstance()
        .withStringPayload(payload)
        .sign(secret)
        .buildJsonFlattened();

    assertTrue(jws.isSignatureValid(secret));
  }
}