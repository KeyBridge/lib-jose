package ch.keybridge.jose.jwe.encryption;

import static ch.keybridge.jose.jwe.encryption.AesCbcHmacSha2Encrypter.Configuration.*;

/**
 * RFC-7518 § 5.1. "enc" (Encryption Algorithm) Header Parameter Values for JWE
 * <p>
 * The table below is the set of "enc" (encryption algorithm) Header Parameter
 * values that are defined by this specification for use with JWE.
 * <p>
 * All also use a JWE Initialization Vector value and produce JWE Ciphertext and
 * JWE Authentication Tag values.
 * <p>
 * RFC-7518 § A.3. Content Encryption Algorithm Identifier Cross-Reference
 * <p>
 * This section contains a table cross-referencing the JWE "enc" (encryption
 * algorithm) values defined in this specification with the equivalent
 * identifiers used by other standards and software packages. For the composite
 * algorithms "A128CBC-HS256", "A192CBC-HS384", and "A256CBC-HS512", the
 * corresponding AES-CBC algorithm identifiers are listed.
 * <pre>
 *    +-------------------------------------------------------------------+
 *    | JWE           | XML ENC                                           |
 *    | | JCA                                   | OID                     |
 *    +-------------------------------------------------------------------+
 *    | A128CBC-HS256 | http://www.w3.org/2001/04/xmlenc#aes128-cbc       |
 *    | | AES/CBC/PKCS5Padding                  | 2.16.840.1.101.3.4.1.2  |
 *    +-------------------------------------------------------------------+
 *    | A192CBC-HS384 | http://www.w3.org/2001/04/xmlenc#aes192-cbc       |
 *    | | AES/CBC/PKCS5Padding                  | 2.16.840.1.101.3.4.1.22 |
 *    +-------------------------------------------------------------------+
 *    | A256CBC-HS512 | http://www.w3.org/2001/04/xmlenc#aes256-cbc       |
 *    | | AES/CBC/PKCS5Padding                  | 2.16.840.1.101.3.4.1.42 |
 *    +-------------------------------------------------------------------+
 *    | A128GCM       | http://www.w3.org/2009/xmlenc11#aes128-gcm        |
 *    | | AES/GCM/NoPadding                     | 2.16.840.1.101.3.4.1.6  |
 *    +-------------------------------------------------------------------+
 *    | A192GCM       | http://www.w3.org/2009/xmlenc11#aes192-gcm        |
 *    | | AES/GCM/NoPadding                     | 2.16.840.1.101.3.4.1.26 |
 *    +-------------------------------------------------------------------+
 *    | A256GCM       | http://www.w3.org/2009/xmlenc11#aes256-gcm        |
 *    | | AES/GCM/NoPadding                     | 2.16.840.1.101.3.4.1.46 |
 *    +-------------------------------------------------------------------+
 * </pre>
 */
public enum EncryptionAlgorithmType {
  /**
   * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in
   * RFC 7518 Section 5.2.3
   */
  A128CBC_HS256("A128CBC-HS256", new AesCbcHmacSha2Encrypter(AES_128_CBC_HMAC_SHA_256)),
  /**
   * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in
   * RFC 7518 Section 5.2.4
   */
  A192CBC_HS384("A192CBC-HS384", new AesCbcHmacSha2Encrypter(AES_192_CBC_HMAC_SHA_384)),
  /**
   * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in
   * RFC 7518 Section 5.2.5
   */
  A256CBC_HS512("A256CBC-HS512", new AesCbcHmacSha2Encrypter(AES_256_CBC_HMAC_SHA_512)),
  /**
   * RFC7518 § 5.3. Content Encryption with AES GCM This section defines the
   * specifics of performing authenticated encryption with AES in Galois/Counter
   * Mode (GCM) ([AES] and [NIST.800-38D]).
   * <p>
   * The CEK is used as the encryption key.
   * <p>
   * Use of an IV of size 96 bits is REQUIRED with this algorithm. The requested
   * size of the Authentication Tag output MUST be 128 bits, regardless of the
   * key size.
   * <p>
   * The following "enc" (encryption algorithm) Header Parameter values are used
   * to indicate that the JWE Ciphertext and JWE Authentication Tag values have
   * been computed using the corresponding algorithm and key size:
   * <pre>
   * +-------------------+------------------------------+
   * | "enc" Param Value | Content Encryption Algorithm |
   * +-------------------+------------------------------+
   * | A128GCM           | AES GCM using 128-bit key    |
   * | A192GCM           | AES GCM using 192-bit key    |
   * | A256GCM           | AES GCM using 256-bit key    |
   * +-------------------+------------------------------+
   * </pre>
   * <p>
   * An example using this algorithm is shown in Appendix A.1 of [JWE].
   * <p>
   * Additional details about these algorithms is available in §5 of
   * <a href="https://www.ietf.org/rfc/rfc5116.txt">RFC 5116</a>.
   */
  A128GCM("A128GCM", new AesGcmEncrypter(128)),
  /**
   * AES GCM using 192-bit key.
   *
   * @see A128GCM
   */
  A192GCM("A192GCM", new AesGcmEncrypter(192)),
  /**
   * AES GCM using 256-bit key
   *
   * @see A128GCM
   */
  A256GCM("A256GCM", new AesGcmEncrypter(256)),
  UNKNOWN(null, null);

  /**
   * The name of the algorithm as per the JWE/JOSE specification
   */
  private final String joseAlgorithmName;
  private final Encrypter encrypter;

  EncryptionAlgorithmType(String joseAlgorithmName, Encrypter encrypter) {
    this.joseAlgorithmName = joseAlgorithmName;
    this.encrypter = encrypter;
  }

  public static EncryptionAlgorithmType resolve(String joseAngorithm) {
    if (joseAngorithm == null || joseAngorithm.isEmpty()) {
      return UNKNOWN;
    }
    for (EncryptionAlgorithmType algorithm : EncryptionAlgorithmType.values()) {
      if (joseAngorithm.equals(algorithm.joseAlgorithmName)) {
        return algorithm;
      }
    }
    return UNKNOWN;
  }

  public String getJoseAlgorithmName() {
    return joseAlgorithmName;
  }

  public Encrypter getEncrypter() {
    return encrypter;
  }
}
