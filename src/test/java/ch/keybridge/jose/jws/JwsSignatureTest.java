package ch.keybridge.jose.jws;

import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.jwk.JwkRsaKey;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.*;

public class JwsSignatureTest {
  @Test
  public void getInstance() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    JWK key = JwkRsaKey.getInstance(keyPair);



    JwsSignature signature = JwsSignature.getInstance("sign this", key, ESignatureAlgorithm.RS256);
    JwsSignature signature2 = JwsSignature.getInstance("sign this", key, ESignatureAlgorithm.RS512);

    System.out.println(signature.getSignature());
    System.out.println(signature2.getSignature());

    String longString = createRandomString(10000);
    JwsSignature signature3 = JwsSignature.getInstance(longString, key, ESignatureAlgorithm.RS512);
    System.out.println(signature3.getSignature());
  }

  @Test
  public void name() throws Exception {
    System.out.println(createRandomString(1));
    System.out.println(createRandomString(10));
    System.out.println(createRandomString(100));
  }

  private static String createRandomString(int length) {
    StringBuilder b = new StringBuilder();
    ThreadLocalRandom r = ThreadLocalRandom.current();
    while (b.length() < length) {
      b.append((char)(r.nextInt(26) + 'a'));
    }
    return b.toString();
  }
}