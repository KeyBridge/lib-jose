package ch.keybridge.jose.jws;

/**
 * RFC 7518 § 3.1. "alg" (Algorithm) Header Parameter Values for JWS
 * <p>
 * The table below is the set of "alg" (algorithm) Header Parameter
 * values defined by this specification for use with JWS, each of which
 * is explained in more detail in the following sections:
 */
public enum ESignatureAlgorithm {
  /**
   * HMAC using SHA-256
   */
  HS256("HS256", "HmacSHA256"),
  /**
   * HMAC using SHA-384
   */
  HS384("HS384", "HmacSHA384"),
  /**
   * HMAC using SHA-512
   */
  HS512("HS512", "HmacSHA512"),
  /**
   * RSASSA-PKCS1-v1_5 using SHA-256
   */
  RS256("RS256", "SHA256withRSA"),
  /**
   * RSASSA-PKCS1-v1_5 using SHA-384
   */
  RS384("RS384", "SHA384withRSA"),
  /**
   * RSASSA-PKCS1-v1_5 using SHA-512
   */
  RS512("RS512", "SHA512withRSA"),
  /**
   * ECDSA using P-256 and SHA-256
   */
  ES256("ES256", "SHA256withECDSA"),
  /**
   * ECDSA using P-384 and SHA-384
   */
  ES284("ES284", "SHA384withECDSA"),
  /**
   * ECDSA using P-521 and SHA-512
   */
  ES512("ES512", "SHA512withECDSA"),
  /**
   * RSASSA-PSS using SHA-256 and MGF1 with SHA-256
   */
//  PS256("PS256", "SHA256withRSAandMGF1"),
  /**
   * RSASSA-PSS using SHA-384 and MGF1 with SHA-384
   */
//  PS384("PS384", "SHA384withRSAandMGF1"),
  /**
   * RSASSA-PSS using SHA-512 and MGF1 with SHA-512
   */
//  PS512("PS512", "SHA512withRSAandMGF1"),
  /**
   * No digital signature or MAC performed
   */
  NONE("none", null),
  /**
   * A special value for cases when the signature algorithm is not supported or implemented
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
   * (algorithm) values defined in the JWS specification with the
   * equivalent identifier in JCA.
   */
  private final String javaAlgorithmName;

  ESignatureAlgorithm(String joseAlgorithmName, String javaAlgorithmName) {
    this.joseAlgorithmName = joseAlgorithmName;
    this.javaAlgorithmName = javaAlgorithmName;
  }

  public static ESignatureAlgorithm resolveAlgorithm(String alg) {
    if (alg == null || alg.isEmpty()) {
      return UNKNOWN;
    }
    for (ESignatureAlgorithm algorithm : ESignatureAlgorithm.values()) {
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
