package org.ietf.jose.jwe;

import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwe.encryption.Encrypter;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.KeyUtility;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.ietf.jose.util.Base64Utility.fromBase64UrlToString;

/**
 * A JWE decryption utility. Accepts a JweJsonFlattened instance, decrypts the ciphertext using a valid key
 * into a DecryptionResult, which in turn allows getting the plainext as string or bytes.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 30/05/2018
 */
public class JweDecryptor {
  private JweJsonFlattened jwe;

  private JweDecryptor(JweJsonFlattened jwe) {
    this.jwe = jwe;
  }

  /**
   * Create new decrypter.
   *
   * @param jwe
   * @return
   */
  public static JweDecryptor createFor(JweJsonFlattened jwe) {
    return new JweDecryptor(jwe);
  }

  /**
   * Decrypt using bytes of the shared secret key used to encrypt they plaintext.
   *
   * @param secret bytes of the shared secret.
   * @return DecryptionResult containing the decrypted plaintext
   * @throws GeneralSecurityException
   */
  public DecryptionResult decrypt(byte[] secret) throws GeneralSecurityException {
    SecretKey key = KeyUtility.convertSecretToKey("AES", secret);
    return decryptGeneric(key);
  }

  /**
   * Decrypt using base64URL-encoded bytes of the shared secret.
   *
   * @param base64UrlEncodedSecret base64URL-encoded bytes of the shared secret
   * @return DecryptionResult containing the decrypted plaintext
   * @throws GeneralSecurityException
   */
  public DecryptionResult decrypt(String base64UrlEncodedSecret) throws GeneralSecurityException {
    SecretKey key = KeyUtility.convertBase64UrlSecretToKey("AES", base64UrlEncodedSecret);
    return decryptGeneric(key);
  }

  /**
   * Decrypt using a (shared) SecretKey
   *
   * @param key a (shared) SecretKey
   * @return DecryptionResult containing the decrypted plaintext
   * @throws GeneralSecurityException
   */
  public DecryptionResult decrypt(SecretKey key) throws GeneralSecurityException {
    return decryptGeneric(key);
  }

  /**
   * Decrypt using a private key
   *
   * @param key a private key
   * @return DecryptionResult containing the decrypted plaintext
   * @throws GeneralSecurityException
   */
  public DecryptionResult decrypt(PrivateKey key) throws GeneralSecurityException {
    return decryptGeneric(key);
  }

  /**
   * Internal decryption method that accepts any Key instance but may fail with keys that
   * are actually invalid for the operation. The public 'decrypt' methods restrict the set
   * of keys that can be used.
   *
   * @param key a Key instance
   * @return decryption results (plaintext)
   * @throws GeneralSecurityException
   */
  private DecryptionResult decryptGeneric(Key key) throws GeneralSecurityException {
    final JweKeyAlgorithmType keyAlgorithm = jwe.getProtectedHeader().getJweKeyAlgorithmType();
    final JweEncryptionAlgorithmType encAlgorithm = jwe.getProtectedHeader().getEnc();
    final Encrypter encrypter = encAlgorithm.getEncrypter();
    final SecretKey aesKey = (SecretKey) CryptographyUtility.unwrapKey(jwe.getEncryptedKey(), key,
        keyAlgorithm.getJavaAlgorithm(), encrypter.getSecretKeyAlgorithm());
    /**
     * Developer note: Additional files may need to be downloaded and copied
     * into the Java installation security directory
     * https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
     */
    byte[] plaintext = encrypter.decrypt(jwe.getCiphertext(), jwe.getInitializationVector(), jwe
            .getAdditionalAuthenticationData(),
        jwe.getAuthenticationTag(), aesKey);
    return new DecryptionResult(plaintext);
  }

  /**
   * A container for the decrypted plaintext. Allows getting it in original form (bytes) or as a string
   */
  public static class DecryptionResult {
    private final byte[] plaintext;

    private DecryptionResult(byte[] plaintext) {
      this.plaintext = plaintext;
    }

    /**
     * Get the plaintext bytes
     *
     * @return plaintext bytes
     */
    public byte[] getAsBytes() {
      return plaintext;
    }

    /**
     * Get the plaintext as string
     *
     * @return plaintext string
     */
    public String getAsString() {
      return fromBase64UrlToString(new String(plaintext, US_ASCII));
    }
  }
}
