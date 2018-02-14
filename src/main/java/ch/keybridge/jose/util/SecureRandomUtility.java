package ch.keybridge.jose.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomUtility {

  public static byte[] generateBits(int numberOfBits) throws NoSuchAlgorithmException {
    int bytes = numberOfBits / 8;
    if (bytes * 8 < numberOfBits) bytes++;
    return generateBytes(bytes);
  }

  public static byte[] generateBytes(int numberOfBytes) throws NoSuchAlgorithmException {
    SecureRandom random = SecureRandom.getInstanceStrong();
    byte[] bytes = new byte[numberOfBytes];
    random.nextBytes(bytes);
    return bytes;
  }
}
