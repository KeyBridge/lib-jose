package org.ietf.jose.jwa;

/**
 * RFC 7518 § 3.1. "alg" (Algorithm) Header Parameter Values for JWS
 * <p>
 * The table below is the set of "alg" (algorithm) Header Parameter values
 * defined by this specification for use with JWS, each of which is explained in
 * more detail in the following sections:
 */
public enum JwsAlgorithmType {
  /**
   * HMAC using SHA-256 (Required)
   */
  HS256("HS256", "HmacSHA256"),
  /**
   * HMAC using SHA-384 (Optional)
   */
  HS384("HS384", "HmacSHA384"),
  /**
   * HMAC using SHA-512 (Optional)
   */
  HS512("HS512", "HmacSHA512"),
  /**
   * RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
   */
  RS256("RS256", "SHA256withRSA"),
  /**
   * RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
   */
  RS384("RS384", "SHA384withRSA"),
  /**
   * RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
   */
  RS512("RS512", "SHA512withRSA"),
  /**
   * ECDSA using P-256 and SHA-256 (Recommended+)
   * <p>
   * (+) the requirement strength is likely to be increased in a future version
   * of the specification
   */
  ES256("ES256", "SHA256withECDSA"),
  /**
   * ECDSA using P-384 and SHA-384 (Optional)
   */
  ES384("ES384", "SHA384withECDSA"),
  /**
   * ECDSA using P-521 and SHA-512 (Optional)
   */
  ES512("ES512", "SHA512withECDSA"),
  /**
   * RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
   *
   * @deprecated not supported by default in all JRE
   */
  PS256("PS256", "SHA256withRSAandMGF1"),
  /**
   * RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
   *
   * @deprecated not supported by default in all JRE
   */
  PS384("PS384", "SHA384withRSAandMGF1"),
  /**
   * RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
   *
   * @deprecated not supported by default in all JRE
   */
  PS512("PS512", "SHA512withRSAandMGF1"),
  /**
   * No digital signature or MAC performed (Optional)
   */
  NONE("none", null),
  /**
   * A special value for cases when the signature algorithm is not supported or
   * implemented.
   */
  UNKNOWN(null, null);

  /**
   * The name of the algorithm as per the JWS/JOSE specification
   */
  private final String joseAlgorithmName;
  /**
   * RFC-7518 § A.1. Content Encryption Algorithm Identifier Cross-Reference
   * <p>
   * This field cross-references the JWS digital signature and MAC "enc"
   * (algorithm) values defined in the JWS specification with the equivalent
   * identifier in JCA.
   */
  private final String javaAlgorithmName;

  JwsAlgorithmType(String joseAlgorithmName, String javaAlgorithmName) {
    this.joseAlgorithmName = joseAlgorithmName;
    this.javaAlgorithmName = javaAlgorithmName;
  }

  public static JwsAlgorithmType resolveAlgorithm(String alg) {
    if (alg == null || alg.isEmpty()) {
      return UNKNOWN;
    }
    for (JwsAlgorithmType algorithm : JwsAlgorithmType.values()) {
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
}
