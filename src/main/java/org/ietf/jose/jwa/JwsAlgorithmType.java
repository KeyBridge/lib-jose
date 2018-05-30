/*
 * Copyright 2018 Key Bridge.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ietf.jose.jwa;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 3.1. "alg" (Algorithm) Header Parameter Values for JWS
 * <p>
 * The table below is the set of "alg" (algorithm) Header Parameter values
 * defined by this specification for use with JWS, each of which is explained in
 * more detail in the following sections:
 * <pre>
 * +--------------+-------------------------------+--------------------+
 * | "alg" Param  | Digital Signature or MAC      | Implementation     |
 * | Value        | Algorithm                     | Requirements       |
 * +--------------+-------------------------------+--------------------+
 * | HS256        | HMAC using SHA-256            | Required           |
 * | HS384        | HMAC using SHA-384            | Optional           |
 * | HS512        | HMAC using SHA-512            | Optional           |
 * | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
 * |              | SHA-256                       |                    |
 * | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
 * |              | SHA-384                       |                    |
 * | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
 * |              | SHA-512                       |                    |
 * | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
 * | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
 * | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
 * | PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
 * |              | MGF1 with SHA-256             |                    |
 * | PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
 * |              | MGF1 with SHA-384             |                    |
 * | PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
 * |              | MGF1 with SHA-512             |                    |
 * | none         | No digital signature or MAC   | Optional           |
 * |              | performed                     |                    |
 * +--------------+-------------------------------+--------------------+
 * </pre>
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
  NONE("none", null);

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
      throw new IllegalArgumentException("Unsupported algorithm: " + alg);
    }
    for (JwsAlgorithmType algorithm : JwsAlgorithmType.values()) {
      if (alg.equals(algorithm.joseAlgorithmName)) {
        return algorithm;
      }
    }
    throw new IllegalArgumentException("Unsupported algorithm: " + alg);
  }

  public String getJavaAlgorithmName() {
    return javaAlgorithmName;
  }

  public String getJoseAlgorithmName() {
    return joseAlgorithmName;
  }
}
