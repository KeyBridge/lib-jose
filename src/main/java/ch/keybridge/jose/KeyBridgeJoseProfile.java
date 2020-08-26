package ch.keybridge.jose;

import org.ietf.jose.JoseProfile;
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwa.JwsAlgorithmType;

/**
 * The Key Bridge JOSE algorithm profile. Declares required compatibility
 * configurations.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 2019-01-15
 * @author Key Bridge
 * @since v1.0.2 rename to KeyBridgeJoseProfile
 */
public class KeyBridgeJoseProfile implements JoseProfile {

  /**
   * {@inheritDoc}
   * <p>
   * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in
   * RFC 7518 Section 5.2.3
   */
  @Override
  public JweEncryptionAlgorithmType getContentEncAlgo() {
    return JweEncryptionAlgorithmType.A128CBC_HS256;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JweKeyAlgorithmType getKeyMgmtAlgAsym() {
    return JweKeyAlgorithmType.RSA1_5;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JweKeyAlgorithmType getKeyMgmtAlgSymmetric() {
    return JweKeyAlgorithmType.A256KW;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JwsAlgorithmType getSignatureAlgAsymmetric() {
    return JwsAlgorithmType.RS256;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JwsAlgorithmType getSignatureAlgSymmetric() {
    return JwsAlgorithmType.HS256;
  }
}
