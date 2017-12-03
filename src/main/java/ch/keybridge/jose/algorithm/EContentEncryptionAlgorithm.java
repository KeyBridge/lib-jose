package ch.keybridge.jose.algorithm;

import javax.crypto.spec.GCMParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * RFC-7518 § 5.1.  "enc" (Encryption Algorithm) Header Parameter Values for JWE
 * <p>
 * The table below is the set of "enc" (encryption algorithm) Header
 * Parameter values that are defined by this specification for use with
 * JWE.
 * <p>
 * All also use a JWE Initialization Vector value and produce JWE
 * Ciphertext and JWE Authentication Tag values.
 */
public enum EContentEncryptionAlgorithm {
  /**
   * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in RFC 7518 Section 5.2.3
   */
  A128CBC_HS256("A128CBC-HS256", "AES/CBC/PKCS5Padding", 128, 128, 0, "AES", null),
  /**
   * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in RFC 7518 Section 5.2.4
   */
  A192CBC_HS384("A192CBC-HS384", "AES/CBC/PKCS5Padding", 192, 128, 0, "AES", null),
  /**
   * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in RFC 7518 Section 5.2.5
   */
  A256CBC_HS512("A256CBC-HS512", "AES/CBC/PKCS5Padding", 256, 128, 0, "AES", null),
  /**
   * RFC7518 § 5.3.  Content Encryption with AES GCM
   * This section defines the specifics of performing authenticated
   * encryption with AES in Galois/Counter Mode (GCM) ([AES] and
   * [NIST.800-38D]).
   * <p>
   * The CEK is used as the encryption key.
   * <p>
   * Use of an IV of size 96 bits is REQUIRED with this algorithm.
   * The requested size of the Authentication Tag output MUST be 128 bits,
   * regardless of the key size.
   * <p>
   * The following "enc" (encryption algorithm) Header Parameter values
   * are used to indicate that the JWE Ciphertext and JWE Authentication
   * Tag values have been computed using the corresponding algorithm and
   * key size:
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
  A128GCM("A128GCM", "AES/GCM/NoPadding", 128, 96, 128, "AES", initVector -> new GCMParameterSpec(128, initVector)),
  A192GCM("A192GCM", "AES/GCM/NoPadding", 192, 96, 128, "AES", initVector -> new GCMParameterSpec(128, initVector)),
  A256GCM("A256GCM", "AES/GCM/NoPadding", 256, 96, 128, "AES", initVector -> new GCMParameterSpec(128, initVector)),
  UNKNOWN(null, null, 0, 0, 0, null, null);

  /**
   * The name of the algorithm as per the JWE/JOSE specification
   */
  private final String joseAlgorithmName;
  /**
   * RFC-7518 § A.3. Content Encryption Algorithm Identifier Cross-Reference
   * <p>
   * This field cross-references the JWE "enc"
   * (encryption algorithm) values defined in the JWE specification with the
   * equivalent identifier in JCA.
   * <p>
   * For the composite algorithms "A128CBC-HS256", "A192CBC-HS384", and
   * "A256CBC-HS512", the corresponding AES-CBC algorithm identifiers are
   * listed.
   */
  private final String javaAlgorithmName;
  /**
   * Required number of bits in the encryption key
   */
  private final int encryptionKeyBits;
  /**
   * Required number of bits in the initialization vector
   */
  private final int initializationVectorBits;
  /**
   * Required number of bits in the authentication tag
   */
  private final int authenticationTagBits;
  /**
   * The SecretKeySpec constructor requires the algorithm transformation without the
   * mode and padding bits. For example, for the AES/GCM/NoPadding encryption scheme
   * the constructor only needs AES, hence this is stored separately.
   */
  private final String secretKeySpecificationAlgorithm;
  /**
   * If the encryption method requires an AlgorithmParameterSpec instance, this
   * method is used to create one from a provided initialization vector. Otherwise,
   * this field is null;
   */
  private final AlgorithmParameterSpecGenerator additionalParameterGenerator;

  EContentEncryptionAlgorithm(String joseAlgorithmName, String javaAlgorithmName, int encryptionKeyBits, int
      initializationVectorBits, int authenticationTagBits, String secretKeySpecificationAlgorithm,
                              AlgorithmParameterSpecGenerator

                                 additionalParameterGenerator) {
    this.joseAlgorithmName = joseAlgorithmName;
    this.javaAlgorithmName = javaAlgorithmName;
    this.encryptionKeyBits = encryptionKeyBits;
    this.initializationVectorBits = initializationVectorBits;
    this.authenticationTagBits = authenticationTagBits;
    this.secretKeySpecificationAlgorithm = secretKeySpecificationAlgorithm;
    this.additionalParameterGenerator = additionalParameterGenerator;
  }

  public static EContentEncryptionAlgorithm resolveAlgorithm(String alg) {
    if (alg == null || alg.isEmpty()) {
      return UNKNOWN;
    }
    for (EContentEncryptionAlgorithm algorithm : EContentEncryptionAlgorithm.values()) {
      if (alg.equals(algorithm.joseAlgorithmName)) {
        return algorithm;
      }
    }
    return UNKNOWN;
  }

  public String getJavaAlgorithmName() {
    return javaAlgorithmName;
  }

  public String getJoseAlgorithmName() {
    return joseAlgorithmName;
  }

  public boolean hasAdditionalParameters() {
    return additionalParameterGenerator != null;
  }

  public int getEncryptionKeyBits() {
    return encryptionKeyBits;
  }

  public int getInitVectorBits() {
    return initializationVectorBits;
  }

  public int getAuthenticationTagBits() {
    return authenticationTagBits;
  }

  public String getSecretKeyAlgorithm() {
    return secretKeySpecificationAlgorithm;
  }

  public AlgorithmParameterSpecGenerator getAdditionalParameterGenerator() {
    return additionalParameterGenerator;
  }

  public interface AlgorithmParameterSpecGenerator {
    AlgorithmParameterSpec generateSpec(byte[] initVector);
  }
}
