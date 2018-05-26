package ch.keybridge.jose.jwe.encryption;

import java.security.GeneralSecurityException;
import java.security.Key;

/**
 * An interface for encapsulating encryption and decryption algorithms.
 */
public interface Encrypter {

  /**
   * Generate a valid key for the algorithm
   *
   * @return a valid encryption key
   * @throws GeneralSecurityException
   */
  Key generateKey() throws GeneralSecurityException;

  /**
   * Encrypt the provided payload bytes using the provided initialisation
   * vector, additional authenticated data, and key.
   *
   * @param payload payload bytes
   * @param iv      initialisation vector. Implementations should generate a
   *                valid initialisation vector automatically in case a null IV
   *                is provided.
   * @param aad     additional authenticated data
   * @param key     a valid encryption key.
   * @return
   * @throws GeneralSecurityException encryption operation failed
   */
  EncryptionResult encrypt(byte[] payload, byte[] iv, byte[] aad, Key key) throws GeneralSecurityException;

  /**
   * Decrypt the ciphertext using the provided initialisation vector, additional
   * authenticated data, and key.
   *
   * @param ciphertext ciphertext bytes
   * @param iv         initialisation vector used during encryption
   * @param aad        additional authenticated data
   * @param authTag    authentication tag obtained during encryption
   * @param key        key used to encrypt the plaintext
   * @return plaintext bytes
   * @throws GeneralSecurityException encryption operation failed
   */
  byte[] decrypt(byte[] ciphertext, byte[] iv, byte[] aad, byte[] authTag, Key key) throws GeneralSecurityException;
}
