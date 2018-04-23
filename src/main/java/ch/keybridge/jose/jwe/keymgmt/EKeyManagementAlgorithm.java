package ch.keybridge.jose.jwe.keymgmt;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

/**
 * RFC-7518 § 4.1.  "alg" (Algorithm) Header Parameter Values for
 * <p>
 * The table below is the set of "alg" (algorithm) Header Parameter
 * values that are defined by this specification for use with JWE.
 * These algorithms are used to encrypt the CEK, producing the JWE
 * Encrypted Key, or to use key agreement to agree upon the CEK
 */
public enum EKeyManagementAlgorithm {

  RSA1_5("RSA1_5", "RSA/ECB/PKCS1Padding"),
  RSA_OAEP("RSA-OAEP", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
  RSA_OAEP_256("RSA-OAEP-256", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
      new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)),
  ECDH_ES("ECDH-ES", "ECDH"),
  A128KW("A128KW", "AESWrap"),
  A192KW("A192KW", "AESWrap"),
  A256KW("A256KW", "AESWrap"),
  UNKNOWN(null, null);

  /**
   * The name of the algorithm as per the JWE/JOSE specification
   */
  private final String joseAlgorithmName;
  /**
   * A.2.  Key Management Algorithm Identifier Cross-Reference
   * This section contains a table cross-referencing the JWE "alg"
   * (algorithm) values defined in this specification with the equivalent
   * identifiers used by other standards and software packages.
   */
  private final String javaAlgorithmName;
  private final AlgorithmParameterSpec additionalParameters;

  EKeyManagementAlgorithm(String joseAlgorithmName, String javaAlgorithmName, AlgorithmParameterSpec additionalParameters) {
    this.joseAlgorithmName = joseAlgorithmName;
    this.javaAlgorithmName = javaAlgorithmName;
    this.additionalParameters = additionalParameters;
  }

  EKeyManagementAlgorithm(String joseAlgorithmName, String javaAlgorithmName) {
    this(joseAlgorithmName, javaAlgorithmName, null);
  }

  public static EKeyManagementAlgorithm resolveAlgorithm(String alg) {
    if (alg == null || alg.isEmpty()) {
      return UNKNOWN;
    }
    for (EKeyManagementAlgorithm algorithm : EKeyManagementAlgorithm.values()) {
      if (alg.equals(algorithm.joseAlgorithmName)) {
        return algorithm;
      }
    }
    return UNKNOWN;
  }

  public String getJavaAlgorithm() {
    return javaAlgorithmName;
  }

  public String getJoseAlgorithmName() {
    return joseAlgorithmName;
  }

  public AlgorithmParameterSpec getAdditionalParameters() {
    return additionalParameters;
  }

  public boolean hasAdditionalParameters() {
    return additionalParameters != null;
  }
}
