package ch.keybridge.jose.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomUtility {

  public static byte[] generate(int numberOfBits) throws NoSuchAlgorithmException {
    SecureRandom random = SecureRandom.getInstanceStrong();
    byte[] bytes = new byte[numberOfBits / 8];
    random.nextBytes(bytes);
    return bytes;
  }
}
