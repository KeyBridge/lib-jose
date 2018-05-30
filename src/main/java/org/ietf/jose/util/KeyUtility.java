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
    return new SecretKeySpec(secret, algorithm);
  }
}
