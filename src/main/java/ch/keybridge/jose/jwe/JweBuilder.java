package ch.keybridge.jose.jwe;

import ch.keybridge.jose.jwe.encryption.EEncryptionAlgo;
import ch.keybridge.jose.jwe.keymgmt.EKeyManagementAlgorithm;
import ch.keybridge.jose.util.Base64Utility;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import static ch.keybridge.jose.util.Base64Utility.toBase64Url;
import static java.nio.charset.StandardCharsets.US_ASCII;

public class JweBuilder {
  /**
   * Default algorithms
   */
  private static final EEncryptionAlgo CONTENT_ENC_ALGO = EEncryptionAlgo.A256GCM;
  private static final EKeyManagementAlgorithm KEY_MGMT_ALGO_ASYM = EKeyManagementAlgorithm.RSA_OAEP;

  private EEncryptionAlgo encryptionAlgo = CONTENT_ENC_ALGO;
  /**
   * Cannot set a default Key Management algorithm at this point because we don't know if
   * a symmetric or asymmetric key will be used for payload encryption.
   */
  private EKeyManagementAlgorithm keyMgmtAlgo;
  private JweJoseHeader protectedHeader = new JweJoseHeader();
  private JweJoseHeader unprotectedHeader;
  private byte[] payload;

  private JweBuilder() {
  }

  public static JweBuilder getInstance() {
    return new JweBuilder();
  }

  /**
   * Create an AES secret key instance from a Base64URL encoded string
   *
   * @param base64UrlEncodedSecret
   * @return
   */
  public static SecretKey createSecretKey(String base64UrlEncodedSecret) {
    byte[] secretBytes = Base64Utility.fromBase64Url(base64UrlEncodedSecret);
    return new SecretKeySpec(secretBytes, "AES");
  }

  /**
   * Resolve the Key Management algorithm from the SecretKey length (16, 24, or 32).
   * This only applies for symmetric encryption (wrapping) of encryption keys.
   *
   * @param key non-nul SecretKey instance
   * @return
   */
  private static EKeyManagementAlgorithm resolveSecretKeyAlgorithm(SecretKey key) {
    switch (key.getEncoded().length) {
      case 16:
        return EKeyManagementAlgorithm.A128KW;
      case 24:
        return EKeyManagementAlgorithm.A192KW;
      case 32:
        return EKeyManagementAlgorithm.A256KW;
      default:
        throw new IllegalArgumentException("Key length not 128/192/256 bits.");
    }
  }

  public JweBuilder withBinaryPayload(byte[] payload) {
    this.payload = payload;
    return this;
  }

  public JweBuilder withStringPayload(String payload) {
    this.payload = toBase64Url(payload).getBytes(US_ASCII);
    return this;
  }

  public JweBuilder withProtectedHeader(JweJoseHeader header) {
    protectedHeader = header;
    return this;
  }

  public JweBuilder withUnprotectedHeader(JweJoseHeader header) {
    unprotectedHeader = header;
    return this;
  }

  public JweBuilder withEncryptionAlgorithm(EEncryptionAlgo algorithm) {
    encryptionAlgo = algorithm;
    return this;
  }

  public JweBuilder withKeyManagementAlgorithm(EKeyManagementAlgorithm algorithm) {
    keyMgmtAlgo = algorithm;
    return this;
  }

  public JweJsonFlattened buildJweJsonFlattened(PublicKey key) throws IOException, GeneralSecurityException {
    if (keyMgmtAlgo == null) keyMgmtAlgo = KEY_MGMT_ALGO_ASYM;
    return JweJsonFlattened.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
        protectedHeader, unprotectedHeader);
  }

  public JweJsonFlattened buildJweJsonFlattened(SecretKey key) throws IOException, GeneralSecurityException {
    keyMgmtAlgo = resolveSecretKeyAlgorithm(key);
    return JweJsonFlattened.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
        protectedHeader, unprotectedHeader);
  }

  public JweJsonFlattened buildJweJsonFlattened(String base64UrlEncodedSecret) throws IOException,
      GeneralSecurityException {
    SecretKey key = createSecretKey(base64UrlEncodedSecret);
    keyMgmtAlgo = resolveSecretKeyAlgorithm(key);
    return JweJsonFlattened.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key, protectedHeader, unprotectedHeader);
  }
}
