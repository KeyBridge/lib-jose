package org.ietf.jose.jwe;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import org.ietf.jose.util.KeyUtility;

/**
 * A utility for building AES SecretKeys from various strings. Supports
 * arbitrary, base64URL, and hexBinary strings. Caveat: the user must know what
 * string they are passing: this builder does not automatically recognize
 * whether a string is base64Url, hexBinary, or just an arbitrary string.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 2018-12-13
 */
public class SecretKeyBuilder {

  /**
   * The only secret key algorithm currently supported.
   */
  public static final String ALGORITHM = "AES";

  /**
   * Create an AES secret key from base64URL-encoded bytes.
   *
   * @param base64UrlEncodedSecret base64URL string
   * @return an EAS secret key
   */
  public static SecretKey fromBase64UrlEncodedString(String base64UrlEncodedSecret) {
    return KeyUtility.convertBase64UrlSecretToKey(ALGORITHM, base64UrlEncodedSecret);
  }

  /**
   * Create an AES secret key from hexBinary-encoded bytes.
   *
   * @param hexBinaryEncodedSecret hexBinary string
   * @return an EAS secret key
   */
  public static SecretKey fromHexBinaryString(String hexBinaryEncodedSecret) {
    HexBinaryAdapter adapter = new HexBinaryAdapter();
    byte[] secret = adapter.unmarshal(hexBinaryEncodedSecret);
    return KeyUtility.convertSecretToKey(ALGORITHM, secret);
  }

  /**
   * Create an AES secret key from an arbitrary string value. This method is
   * typically used for shared secret authentication, where the shared secret
   * format is determined by content and may not conform with JOSE length
   * requirements.
   * <p>
   * A SHA-256 hash is calculated from the supplied string in order to obtain a
   * good number of bytes (AES keys can be 16, 24, or 32 bytes in length) for
   * the AES key.
   *
   * @param sharedSecret a (shared) secret string value
   * @return an AES secret key
   * @throws java.security.NoSuchAlgorithmException if no Provider supports a
   *                                                MessageDigestSpi
   *                                                implementation for the
   *                                                'SHA-256' algorithm. Note:
   *                                                this should NEVER be thrown
   *                                                as all JRE implementations
   *                                                MUST support SHA-256.
   */
  public static SecretKey fromSharedSecret(String sharedSecret) throws NoSuchAlgorithmException {
    byte[] secret = java.security.MessageDigest.getInstance("SHA-256")
      .digest(sharedSecret.getBytes(StandardCharsets.UTF_8));
    return KeyUtility.convertSecretToKey(ALGORITHM, secret);
  }

  /**
   * Create and AES secret key from a byte array.
   *
   * @param secret some bytes representing a secret
   * @return an EAS secret key
   */
  public static SecretKey fromBytes(byte[] secret) {
    return KeyUtility.convertSecretToKey(ALGORITHM, secret);
  }
}
