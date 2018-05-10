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
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/01/2018
 */
public class AesGcmEncrypter implements Encrypter {

  /**
   * The authentication tag length (in bits). "Strongly recommended to keep it
   * at 12 bytes = 96 bits"
   * <p>
   * The GCM specification states that tLen may only have the values {128, 120,
   * 112, 104, 96}, or {64, 32} for certain applications. Other values can be
   * specified for this class, but not all CSP implementations will support
   * them.
   */
  final static int IV_LENGTH = 96;
  final static int IV_BYTE_LENGTH = IV_LENGTH / 8;
  final static int AUTH_TAG_LEN = 128 / 8; //todo
  private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
  private static final String SECRET_KEY_ALGORITHM = "AES";
  final int ENC_KEY_LEN;

  public AesGcmEncrypter(int ENC_KEY_LEN) {
    this.ENC_KEY_LEN = ENC_KEY_LEN;
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

  @Override
  public Key generateKey() throws GeneralSecurityException {
    return new SecretKeySpec(SecureRandomUtility.generateBytes(ENC_KEY_LEN / 8), SECRET_KEY_ALGORITHM);
//    KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
//    generator.init(ENC_KEY_LEN);
//    return generator.generateKey();
  }

  @Override
  public EncryptionResult encrypt(byte[] payload, byte[] iv, byte[] aad, Key key) throws GeneralSecurityException {
    if (iv == null) {
      iv = SecureRandomUtility.generateBytes(IV_BYTE_LENGTH);
    }
    if (aad == null) {
      aad = new byte[0];
    }
    validateInputs(key, aad, iv);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(IV_LENGTH, iv));
    cipher.updateAAD(aad);
    byte[] ciphertextWithAad = cipher.doFinal(payload);
//    if (ciphertextWithAad.length != payload.length + AUTH_TAG_LEN)
//      throw new IllegalStateException("Unexpected ciphertext length");
    byte[] ciphertext = Arrays.copyOf(ciphertextWithAad, payload.length);
    byte[] authenticationTag = Arrays.copyOfRange(ciphertextWithAad, payload.length, ciphertextWithAad.length);
    return new EncryptionResult(iv, aad, ciphertext, authenticationTag);
  }

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
