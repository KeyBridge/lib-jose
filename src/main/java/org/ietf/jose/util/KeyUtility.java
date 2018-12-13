package org.ietf.jose.util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A utility class for obtaining keys from raw bytes or strings
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 30/05/2018
 */
public class KeyUtility {

  /**
   * Convert a base64URL-encoded secret into a Key
   *
   * @param algorithm              JCA secret key algorithm
   * @param base64UrlEncodedSecret base64UrlEncodedSecret
   * @return a SecretKey instance
   */
  public static SecretKey convertBase64UrlSecretToKey(String algorithm, String base64UrlEncodedSecret) {
    byte[] secret = Base64Utility.fromBase64Url(base64UrlEncodedSecret);
    /**
     * Constructs a secret key from the given byte array.
     */
    return new SecretKeySpec(secret, algorithm);
  }

  /**
   * Convert a base64URL-encoded secret into a Key
   *
   * @param algorithm JCA secret key algorithm
   * @param secret    bytes of the secret used to create the HMAC
   * @return a SecretKey instance
   */
  public static SecretKey convertSecretToKey(String algorithm, byte[] secret) {
    /**
     * Constructs a secret key from the given byte array.
     * <p>
     * This constructor does not check if the given bytes indeed specify a
     * secret key of the specified algorithm. For example, if the algorithm is
     * DES, this constructor does not check if key is 8 bytes long, and also
     * does not check for weak or semi-weak keys. In order for those checks to
     * be performed, an algorithm-specific key specification class (in this
     * case: DESKeySpec) should be used.
     */
    return new SecretKeySpec(secret, algorithm);
  }
}
