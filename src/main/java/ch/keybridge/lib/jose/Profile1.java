package ch.keybridge.lib.jose;

import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwa.JwsAlgorithmType;

/**
 * The first version if the JOSE algorithm profile.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 2019-01-15
 */
public class Profile1 implements Profile {
  /**
   * @inheritDoc
   */
  @Override
  public JweEncryptionAlgorithmType getContentEncAlgo() {
    return JweEncryptionAlgorithmType.A128CBC_HS256;
  }

  /**
   * @inheritDoc
   */
  @Override
  public JweKeyAlgorithmType getKeyMgmtAlgAsym() {
    return JweKeyAlgorithmType.RSA1_5;
  }

  /**
   * @inheritDoc
   */
  @Override
  public JweKeyAlgorithmType getKeyMgmtAlgSymmetric() {
    return JweKeyAlgorithmType.A256KW;
  }

  /**
   * @inheritDoc
   */
  @Override
  public JwsAlgorithmType getSignatureAlgAsymmetric() {
    return JwsAlgorithmType.RS256;
  }

  /**
   * @inheritDoc
   */
  @Override
  public JwsAlgorithmType getSignatureAlgSymmetric() {
    return JwsAlgorithmType.HS256;
  }
}
