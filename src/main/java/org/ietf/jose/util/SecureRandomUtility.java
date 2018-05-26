package org.ietf.jose.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * A SecureRandom utility to generate random bits and bytes.
 * <p>
 * When using SecureRandom you must ALWAYS specify a number generator algorithm.
 * <p>
 * Tested working algorithms: NativePRNGNonBlocking, SHA1PRNG
 *
 * @author Key Bridge
 * @see
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecureRandom">SecureRandom</a>
 */
public class SecureRandomUtility {

  /**
   * Generate a sequence of random bits. This is a shortcut method to
   * {@code generateBytes}.
   *
   * @param numberOfBits the number of bits to generate
   * @return a byte array
   * @throws NoSuchAlgorithmException if the JRE/JDK does not support the
   *                                  {@code SHA1PRNG} SecureRandom Number
   *                                  Generation Algorithms (highly unlikely
   *                                  since this is the JRE default)
   */
  public static byte[] generateBits(int numberOfBits) throws NoSuchAlgorithmException {
    int bytes = numberOfBits / 8;
    if (bytes * 8 < numberOfBits) {
      bytes++;
    }
    return generateBytes(bytes);
  }

  /**
   * Generate a sequence of random bytes.
   * <p>
   * This uses an internal SecureRandom object with the {@code SHA1PRNG} Number
   * Generation Algorithm.
   *
   * @param numberOfBytes the number of bytes to generate
   * @return a byte array
   * @throws NoSuchAlgorithmException if the JRE/JDK does not support the
   *                                  {@code SHA1PRNG} SecureRandom Number
   *                                  Generation Algorithms (highly unlikely
   *                                  since this is the JRE default)
   */
  public static byte[] generateBytes(int numberOfBytes) throws NoSuchAlgorithmException {
    /**
     * Developer note: do NOT call getInstance or getInstanceStrong. These will
     * HANG on linux systems. See bug JDK-6521844 : SecureRandom hangs on Linux
     * Systems (JDK7)
     * <p>
     * The JCK test api/java_security/SecureRandom/SecureRandomTests.html#misc
     * can hang on Linux platforms if there is no other activity on the system.
     * This bug appears to have been in the system for several releases. This is
     * caused by code in the NativePRNG.java file accessing /dev/random and
     * blocking. I believe these suspect code is this method.
     * <p>
     * This can hang indefinitely on Linux. Hanging at generateSeed is not a
     * bug, since that's what was designed: When the entropy pool is empty,
     * reads from /dev/random will block until additional environmental noise is
     * gathered. (Source: Linux Programmer's Manual, section 4).
     * <p>
     * When using SecureRandom you must ALWAYS specify a number generator
     * algorithm.
     * <p>
     * Tested and working algorithms: NativePRNGNonBlocking, SHA1PRNG
     */
//    SecureRandom random = SecureRandom.getInstanceStrong();  // DO NOT USE
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    byte[] bytes = new byte[numberOfBytes];
    random.nextBytes(bytes);
    return bytes;
  }
}
