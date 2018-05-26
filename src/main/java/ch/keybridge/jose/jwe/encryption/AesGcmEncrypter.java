package ch.keybridge.jose.jwe.encryption;

import ch.keybridge.jose.util.SecureRandomUtility;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A content encrypter that uses AES as the block cipher and Galois/Counter mode
 * as the mode of operation.
 * <p>
 * RFC 7518 § 5.3. Content Encryption with AES GCM
 * <p>
 * This section defines the specifics of performing authenticated encryption
 * with AES in Galois/Counter Mode (GCM) ([AES] and [NIST.800-38D]).
 * <p>
 * The CEK is used as the encryption key.
 * <p>
 * Use of an IV of size 96 bits is REQUIRED with this algorithm.
 * <p>
 * The requested size of the Authentication Tag output MUST be 128 bits,
 * regardless of the key size.
 * <p>
 * The following "enc" (encryption algorithm) Header Parameter values are used
 * to indicate that the JWE Ciphertext and JWE Authentication Tag values have
 * been computed using the corresponding algorithm and key size:
 * <pre>
 * +-------------------+------------------------------+
 * | "enc" Param Value | Content Encryption Algorithm |
 * +-------------------+------------------------------+
 * | A128GCM           | AES GCM using 128-bit key    |
 * | A192GCM           | AES GCM using 192-bit key    |
 * | A256GCM           | AES GCM using 256-bit key    |
 * +-------------------+------------------------------+
 * </pre>
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/01/2018
 * @deprecated v0.3.0 AES+GCM may not be included in all JVMs and is not
 * recommended unless specifically required.
 */
@Deprecated // May not be included in all JVMs and hence not recommended
public class AesGcmEncrypter implements Encrypter {

  /**
   * Use of an initialization vector (IV) of size 96 bits is REQUIRED with this
   * algorithm.
   */
  private final static int IV_LENGTH = 96;
  /**
   * Store the IV length in bytes for convenience
   */
  private final static int IV_BYTE_LENGTH = IV_LENGTH / 8;
  /**
   * The requested size of the Authentication Tag output MUST be 128 bits,
   * regardless of the key size.
   */
  private final static int AUTH_TAG_LEN = 128 / 8;
  /**
   * The transformation name for this encryption scheme as per the Java
   * Cryptographic Extension (JCE) framework
   *
   * @see Cipher
   * @see
   * <a href="https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">Cipher
   * documentation</a>
   */
  private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
  /**
   * Secret key algorithm for AES encryption
   */
  private static final String SECRET_KEY_ALGORITHM = "AES";
  /**
   * Length (in bits) of the AES key size. Must be 128, 192, or 256 bits.
   */
  private final int ENC_KEY_LEN;

  /**
   * Create an instance of a content encrypter that uses AES as the block cipher
   * and Galois/Counter mode as the mode of operation.
   *
   * @param encryptionKeySize Size (in bits) of the AES key size. Must be 128,
   *                          192, or 256 bits.
   */
  public AesGcmEncrypter(int encryptionKeySize) {
    if (!(encryptionKeySize == 128 || encryptionKeySize == 192 || encryptionKeySize == 256)) {
      throw new IllegalArgumentException("An AES encryption key must be 128, 192, or 256 bits in length. Length "
        + "provided: " + encryptionKeySize);
    }
    this.ENC_KEY_LEN = encryptionKeySize;
  }

  /**
   * A utility method for array concatenation. Used to concatenate the
   * ciphertext and authentication tag bytes before decrypting.
   *
   * @param array1 first byte array
   * @param array2 second byte array
   * @return byte array with all elements from the first array, the those of the
   *         second array
   */
  public static byte[] concatenateArrays(byte[] array1, byte[] array2) {
    if (array1 == null || array1.length == 0) {
      return array2;
    }
    if (array2 == null || array2.length == 0) {
      return array1;
    }
    byte[] merged = new byte[array1.length + array2.length];
    System.arraycopy(array1, 0, merged, 0, array1.length);
    System.arraycopy(array2, 0, merged, array1.length, array2.length);
    return merged;
  }

  /**
   * Generate a secret key (encryption key) which is valid for this encrypter.
   *
   * @return a valid AES key
   * @throws GeneralSecurityException if AES is not available as the
   *                                  SecretKeySpec algorithm
   */
  @Override
  public Key generateKey() throws GeneralSecurityException {
    return new SecretKeySpec(SecureRandomUtility.generateBytes(ENC_KEY_LEN / 8), SECRET_KEY_ALGORITHM);
  }

  /**
   * @param payload bytes of the plaintext (data that is to be encrypted)
   * @param iv      Initialization vector: random bytes used to initialise the
   *                encryption algorithm.
   * @param aad     Additional authenticated data: bytes of data that is not
   *                encrypted (i.e. remains in plaintext) but its integrity is
   *                ensured by the authenticated encryption algorithm.
   * @param key     An AES secret key
   * @return A DTO containing the initialisation vector (IV), the addidional
   *         authenticated data (same as input)
   * @throws GeneralSecurityException
   */
  @Override
  public EncryptionResult encrypt(final byte[] payload, byte[] iv, byte[] aad, final Key key)
    throws GeneralSecurityException {
    /**
     * Automatically generate an initialisation vector of the correct length.
     */
    if (iv == null) {
      iv = SecureRandomUtility.generateBytes(IV_BYTE_LENGTH);
    }
    validateInputs(key, aad, iv);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(IV_LENGTH, iv));
    cipher.updateAAD(aad);
    byte[] ciphertextWithAad = cipher.doFinal(payload);
    int ciphertextBytes = ciphertextWithAad.length - AUTH_TAG_LEN;
    byte[] ciphertext = Arrays.copyOf(ciphertextWithAad, ciphertextBytes);
    byte[] authenticationTag = Arrays.copyOfRange(ciphertextWithAad, ciphertextBytes, ciphertextWithAad.length);
    return new EncryptionResult(iv, aad, ciphertext, authenticationTag);
  }

  /**
   * Validate inputs (sizes, algorithms)
   *
   * @param key AES secret key
   * @param aad Additional authenticated data
   * @param iv  initialisation vector
   */
  private void validateInputs(Key key, byte[] aad, byte[] iv) {
    if (key.getEncoded().length != ENC_KEY_LEN / 8) {
      throw new IllegalArgumentException("Key must be " + ENC_KEY_LEN / 8 + " bytes in length. Key length:" + key
        .getEncoded().length);
    }
    if (!key.getAlgorithm().equals(SECRET_KEY_ALGORITHM)) {
      throw new IllegalArgumentException("SecretKey must be an AES key");
    }
    if (iv == null || iv.length != IV_BYTE_LENGTH) {
      throw new IllegalArgumentException("Initialisation vector must be " + IV_BYTE_LENGTH + " bytes long. "
        + "Provided IV: " + (iv == null ? null : (iv.length + " bytes. ")));
    }
    if (aad == null || aad.length == 0) {
      throw new IllegalArgumentException("Additional authenticated data must not be empty! "
        + "Provided AAD: " + (aad == null ? null : (aad.length + " bytes. ")));
    }
  }

  /**
   * Decrypt the ciphertext to retrieve the original plaintext. Additional
   * authenticated data and an authentication tag are used as an extra
   * validation step.
   *
   * @param ciphertext ciphertext bytes
   * @param iv         initialisation vector bytes
   * @param aad        additional authenticated data bytes
   * @param authTag    authentication tag (message authentication code)
   * @param key        AES key
   * @return plaintext bytes
   * @throws GeneralSecurityException
   */
  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] iv, byte[] aad, byte[] authTag, Key key) throws
    GeneralSecurityException {
    validateInputs(key, aad, iv);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(IV_LENGTH, iv));
    cipher.updateAAD(aad);
    try {
      return cipher.doFinal(concatenateArrays(ciphertext, authTag));
    } catch (BadPaddingException e) {
      return null;
    }
  }
}
