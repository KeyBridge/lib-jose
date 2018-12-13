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

import java.security.spec.AlgorithmParameterSpec;
import javax.xml.bind.annotation.XmlEnumValue;

/**
 * RFC-7518
 * <p>
 * 4. Cryptographic Algorithms for Key Management
 * <p>
 * JWE uses cryptographic algorithms to encrypt or determine the Content
 * Encryption Key (CEK).
 * <p>
 * 4.1. "alg" (Algorithm) Header Parameter Values for JWE
 * <p>
 * The table below is the set of "alg" (algorithm) Header Parameter values that
 * are defined by this specification for use with JWE. These algorithms are used
 * to encrypt the CEK, producing the JWE Encrypted Key, or to use key agreement
 * to agree upon the CEK.
 * <p>
 * Developer note: This is a partial implementation of the full RFC-7518 table
 * of possible algorithms. This enumerated set is limited to instances known to
 * work in all JVM distributions.
 */
public enum JweKeyAlgorithmType {

  /**
   * 4.2. Key Encryption with RSAES-PKCS1-v1_5
   * <p>
   * This section defines the specifics of encrypting a JWE CEK with
   * RSAES-PKCS1-v1_5 [RFC3447]. The "alg" (algorithm) Header Parameter value
   * "RSA1_5" is used for this algorithm.
   * <p>
   * A key of size 2048 bits or larger MUST be used with this algorithm.
   * <p>
   * An example using this algorithm is shown in Appendix A.2 of [JWE].
   */
  RSA1_5("RSA1_5", "RSA/ECB/PKCS1Padding"),
  /**
   * 4.3. Key Encryption with RSAES OAEP
   * <p>
   * This section defines the specifics of encrypting a JWE CEK with RSAES using
   * Optimal Asymmetric Encryption Padding (OAEP) [RFC3447]. Two sets of
   * parameters for using OAEP are defined, which use different hash functions.
   * In the first case, the default parameters specified in Appendix A.2.1 of
   * RFC 3447 are used. (Those default parameters are the SHA-1 hash function
   * and the MGF1 with SHA-1 mask generation function.) In the second case, the
   * SHA-256 hash function and the MGF1 with SHA-256 mask generation function
   * are used.
   * <p>
   * The following "alg" (algorithm) Header Parameter values are used to
   * indicate that the JWE Encrypted Key is the result of encrypting the CEK
   * using the corresponding algorithm:
   * <pre>
   *    +-------------------+-----------------------------------------------+
   *    | "alg" Param Value | Key Management Algorithm                      |
   *    +-------------------+-----------------------------------------------+
   *    | RSA-OAEP          | RSAES OAEP using default parameters           |
   *    | RSA-OAEP-256      | RSAES OAEP using SHA-256 and MGF1 with        |
   *    |                   | SHA-256                                       |
   *    +-------------------+-----------------------------------------------+
   * </pre>
   * <p>
   * A key of size 2048 bits or larger MUST be used with these algorithms. (This
   * requirement is based on Table 4 (Security-strength time frames) of NIST SP
   * 800-57 [NIST.800-57], which requires 112 bits of security for new uses, and
   * Table 2 (Comparable strengths) of the same, which states that 2048-bit RSA
   * keys provide 112 bits of security.)
   * <p>
   * An example using RSAES OAEP with the default parameters is shown in
   * Appendix A.1 of [JWE].
   */
  @XmlEnumValue("RSA-OAEP")
  RSA_OAEP("RSA-OAEP", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
  /**
   * 4.4. Key Wrapping with AES Key Wrap
   * <p>
   * This section defines the specifics of encrypting a JWE CEK with the
   * Advanced Encryption Standard (AES) Key Wrap Algorithm [RFC3394] using the
   * default initial value specified in Section 2.2.3.1 of that document.
   * <p>
   * The following "alg" (algorithm) Header Parameter values are used to
   * indicate that the JWE Encrypted Key is the result of encrypting the CEK
   * using the corresponding algorithm and key size:
   * <pre>
   * +-----------------+-------------------------------------------------+
   * | "alg" Param     | Key Management Algorithm                        |
   * +-----------------+-------------------------------------------------+
   * | A128KW          | AES Key Wrap with default initial value using   |
   * |                 | 128-bit key                                     |
   * | A192KW          | AES Key Wrap with default initial value using   |
   * |                 | 192-bit key                                     |
   * | A256KW          | AES Key Wrap with default initial value using   |
   * |                 | 256-bit key                                     |
   * +-----------------+-------------------------------------------------+
   * </pre> An example using this algorithm is shown in Appendix A.3 of [JWE].
   */
  A128KW("A128KW", "AESWrap"),
  /**
   * AES Key Wrap with default initial value using 192-bit key.
   *
   * @see A128KW
   */
  A192KW("A192KW", "AESWrap"),
  /**
   * AES Key Wrap with default initial value using 256-bit key.
   *
   * @see A128KW
   */
  A256KW("A256KW", "AESWrap"),
  /**
   * Unknown or unsupported algorithms resolve to UNSUPPORTED
   */
  UNSUPPORTED(null, null);

  /**
   * The name of the algorithm as per the JWE/JOSE specification
   */
  private final String joseAlgorithmName;
  /**
   * A.2. Key Management Algorithm Identifier Cross-Reference
   * <p>
   * This section contains a table cross-referencing the JWE "alg" (algorithm)
   * values defined in this specification with the equivalent identifiers used
   * by other standards and software packages.
   */
  private final String javaAlgorithmName;
  /**
   * A (transparent) specification of cryptographic parameters. Additional
   * parameters are required by some algorithms.
   */
  private final AlgorithmParameterSpec additionalParameters;

  JweKeyAlgorithmType(String joseAlgorithmName, String javaAlgorithmName, AlgorithmParameterSpec additionalParameters) {
    this.joseAlgorithmName = joseAlgorithmName;
    this.javaAlgorithmName = javaAlgorithmName;
    this.additionalParameters = additionalParameters;
  }

  JweKeyAlgorithmType(String joseAlgorithmName, String javaAlgorithmName) {
    this(joseAlgorithmName, javaAlgorithmName, null);
  }

  /**
   * Resolve Key Management Algorithm from the JOSE alg header, e.g. 'A128KW'
   * <p>
   * Returns UNSUPPORTED for incorrect 'alg' values or unsupported key
   * management algorithms
   *
   * @param alg the JOSE algorithm name
   * @return the corresponding JweKeyAlgorithmType instance
   */
  public static JweKeyAlgorithmType resolveAlgorithm(String alg) {
    if (alg == null || alg.isEmpty()) {
      return UNSUPPORTED;
    }
    for (JweKeyAlgorithmType algorithm : JweKeyAlgorithmType.values()) {
      if (alg.equals(algorithm.joseAlgorithmName)) {
        return algorithm;
      }
    }
    return UNSUPPORTED;
  }

  /**
   * Algorithm name as per the Java Cryptography Architecture (JCA)
   *
   * @return the JCA algorithm name
   */
  public String getJavaAlgorithm() {
    return javaAlgorithmName;
  }

  /**
   * 'alg' header value in the JOSE header
   *
   * @return 'alg' header value
   */
  public String getJoseAlgorithmName() {
    return joseAlgorithmName;
  }
}
