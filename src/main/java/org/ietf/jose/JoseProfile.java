package org.ietf.jose;

import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwa.JwsAlgorithmType;

/**
 * A profile is a selection of algorithms used in utility classes, such as
 * JoseFactory.
 *
 * @author Andrius Druzinis-Vitkus
 * @see JoseFactory
 * @since 0.0.1 created 2019-01-15
 * @since v1.0.2 rename to JoseProfile
 */
public interface JoseProfile {

  /**
   * The content encryption algorithm to use in JWEs.
   *
   * @return content encryption algorithm.
   */
  JweEncryptionAlgorithmType getContentEncAlgo();

  /**
   * The key management algorithm when using symmetric key encryption (shared
   * secrets).
   *
   * @return key management algorithm
   */
  JweKeyAlgorithmType getKeyMgmtAlgAsym();

  /**
   * The key management algorithm when using public keys for key encryption.
   *
   * @return key management algorithm
   */
  JweKeyAlgorithmType getKeyMgmtAlgSymmetric();

  /**
   * The digital signature algorithm.
   *
   * @return digital signature algorithm
   */
  JwsAlgorithmType getSignatureAlgAsymmetric();

  /**
   * The keyed hash (HMAC) algorithm.
   *
   * @return HMAC algorithm
   */
  JwsAlgorithmType getSignatureAlgSymmetric();
}
