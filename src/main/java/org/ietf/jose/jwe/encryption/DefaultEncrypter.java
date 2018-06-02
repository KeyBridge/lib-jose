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
package org.ietf.jose.jwe.encryption;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.ietf.jose.util.SecureRandomUtility;

/**
 * A (default) content encrypter implementation that uses AES as the block
 * cipher and CBC mode as the mode of operation.
 * <p>
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 5.2. AES_CBC_HMAC_SHA2 Algorithms
 * <p>
 * This section defines a family of authenticated encryption algorithms built
 * using a composition of AES [AES] in Cipher Block Chaining (CBC) mode
 * [NIST.800-38A] with PKCS #7 padding operations per Section 6.3 of [RFC5652]
 * and HMAC ([RFC2104] and [SHS]) operations. This algorithm family is called
 * AES_CBC_HMAC_SHA2. It also defines three instances of this family: the first
 * using 128-bit CBC keys and HMAC SHA-256, the second using 192-bit CBC keys
 * and HMAC SHA-384, and the third using 256-bit CBC keys and HMAC SHA-512. Test
 * cases for these algorithms can be found in Appendix B.
 * <p>
 * These algorithms are based upon "Authenticated Encryption with AES- CBC and
 * HMAC-SHA" [AEAD-CBC-SHA], performing the same cryptographic computations, but
 * with the Initialization Vector (IV) and Authentication Tag values remaining
 * separate, rather than being concatenated with the ciphertext value in the
 * output representation. This option is discussed in Appendix B of that
 * specification. This algorithm family is a generalization of the algorithm
 * family in [AEAD-CBC-SHA] and can be used to implement those algorithms.
 * <p>
 * See also (implements):
 * <p>
 * A.3. Content Encryption Algorithm Identifier Cross-Reference
 * <p>
 * | A256CBC-HS512 | http://www.w3.org/2001/04/xmlenc#aes256-cbc | | |
 * AES/CBC/PKCS5Padding | 2.16.840.1.101.3.4.1.42 |
 * <p>
 * https://tools.ietf.org/html/rfc7516#appendix-B
 * https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05#appendix-B
 */
public class DefaultEncrypter implements Encrypter {

  /**
   * Initialisation vector byte length
   */
  final static int IV_BYTE_LENGTH = 128 / 8;
  /**
   * The name of the cipher transformation. See the Cipher section in the Java
   * Cryptography Architecture Standard Algorithm Name Documentation for
   * information about standard transformation names.
   */
  private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  /**
   * The name of the secret-key algorithm to be associated with the given key
   * material. See Appendix A in the Java Cryptography Architecture Reference
   * Guide for information about standard algorithm names.
   */
  private static final String SECRET_KEY_ALGORITHM = "AES";
  /**
   * Immutable configuration parameters for the AES-CBC-HMAC-SHA2 encryption
   * scheme.
   */
  private final AesConfigurationType configuration;

  public DefaultEncrypter(AesConfigurationType configuration) {
    this.configuration = configuration;
  }

  /**
   * Get a default instance using the AES_128_CBC_HMAC_SHA_256 authenticated
   * encryption algorithm, as defined in RFC 7518 Section 5.2.3.
   * <p>
   * This is the preferred default.
   *
   * @return a Content Encryption Algorithm instance
   */
  public static DefaultEncrypter getInstance() {
    return new DefaultEncrypter(AesConfigurationType.AES_128_CBC_HMAC_SHA_256);
  }

  /**
   * Get a default instance using the AES_192_CBC_HMAC_SHA_384 authenticated
   * encryption algorithm, as defined in RFC 7518 Section 5.2.4
   *
   * @return a Content Encryption Algorithm instance
   */
  public static DefaultEncrypter getInstance384() {
    return new DefaultEncrypter(AesConfigurationType.AES_192_CBC_HMAC_SHA_384);
  }

  /**
   * Get a default instance using the AES_256_CBC_HMAC_SHA_512 authenticated
   * encryption algorithm, as defined in RFC 7518 Section 5.2.5
   *
   * @return a Content Encryption Algorithm instance
   */
  public static DefaultEncrypter getInstance512() {
    return new DefaultEncrypter(AesConfigurationType.AES_256_CBC_HMAC_SHA_512);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Key generateKey() throws GeneralSecurityException {
    return new SecretKeySpec(SecureRandomUtility.generateBytes(configuration.INPUT_KEY_LENGTH), SECRET_KEY_ALGORITHM);
  }

  /**
   * {@inheritDoc}
   */
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
    cipher.init(Cipher.ENCRYPT_MODE, generateEncryptionKey(key), new IvParameterSpec(iv));
    final byte[] ciphertext = cipher.doFinal(payload);

    return new EncryptionResult(iv, aad, ciphertext, calculateAuthenticationTag(ciphertext, aad, iv, key));
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] iv, byte[] aad, byte[] authTag, Key key) throws
    GeneralSecurityException {
    if (aad == null) {
      aad = new byte[0];
    }
    validateInputs(key, aad, iv);
    if (!Arrays.equals(authTag, calculateAuthenticationTag(ciphertext, aad, iv, key))) {
      return null;
    }

    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, generateEncryptionKey(key), new IvParameterSpec(iv));
    return cipher.doFinal(ciphertext);
  }

  private byte[] calculateAuthenticationTag(byte[] ciphertext, byte[] aad, byte[] iv, Key key) throws
    GeneralSecurityException {
    final byte[] al = getUnsignedLongBytes(aad.length * 8);
    final byte[] macInput = concatenate(aad, iv, ciphertext, al);
    Mac mac = Mac.getInstance(configuration.JCE_MAC_ALG);
    mac.init(generateMacKey(key));
    byte[] macValue = mac.doFinal(macInput);
    return Arrays.copyOf(macValue, configuration.T_LEN);
  }

  private static byte[] getUnsignedLongBytes(long l) {
    byte[] result = new byte[8];
    for (int i = 7; i >= 0; i--) {
      result[i] = (byte) (l & 0xFF);
      l >>= 8;
    }
    return result;
  }

  private static byte[] concatenate(byte[] aad, byte[] iv, byte[] ciphertext, byte[] a) {
    byte[] output = new byte[aad.length + iv.length + ciphertext.length + a.length];
    int idx = 0;
    System.arraycopy(aad, 0, output, idx, aad.length);
    idx += aad.length;
    System.arraycopy(iv, 0, output, idx, iv.length);
    idx += iv.length;
    System.arraycopy(ciphertext, 0, output, idx, ciphertext.length);
    idx += ciphertext.length;
    System.arraycopy(a, 0, output, idx, a.length);
    return output;
  }

  private void validateInputs(Key key, byte[] aad, byte[] iv) {
    if (key.getEncoded().length != configuration.INPUT_KEY_LENGTH) {
      throw new IllegalArgumentException("Key must be " + configuration.INPUT_KEY_LENGTH + " bytes in length. Key "
        + "length:" + key.getEncoded().length);
    }
    if (!key.getAlgorithm().equals(SECRET_KEY_ALGORITHM)) {
      throw new IllegalArgumentException("SecretKey must be an AES key");
    }
    if (iv == null || iv.length != IV_BYTE_LENGTH) {
      throw new IllegalArgumentException("Initialisation vector must be " + IV_BYTE_LENGTH + " bytes long. "
        + "Provided IV: " + (iv == null ? null : (iv.length + " bytes. ")));
    }
    if (aad == null) {
      throw new IllegalArgumentException("Additional authenticated data must not be null");
    }
  }

  private SecretKey generateMacKey(Key key) {
    return new SecretKeySpec(Arrays.copyOf(key.getEncoded(), configuration.MAC_KEY_LEN), SECRET_KEY_ALGORITHM);
  }

  private SecretKey generateEncryptionKey(Key key) {
    return new SecretKeySpec(Arrays.copyOfRange(key.getEncoded(), configuration.MAC_KEY_LEN, configuration.INPUT_KEY_LENGTH),
                             SECRET_KEY_ALGORITHM);
  }

  /**
   * Immutable configuration parameters for the AES-CBC-HMAC-SHA2 encryption
   * scheme.
   */
  public enum AesConfigurationType {
    AES_128_CBC_HMAC_SHA_256(32, 16, 16, "SHA-256", "HmacSHA256", 16),
    AES_192_CBC_HMAC_SHA_384(48, 24, 24, "SHA-384", "HmacSHA384", 24),
    AES_256_CBC_HMAC_SHA_512(64, 32, 32, "SHA-512", "HmacSHA512", 32);

    public final int INPUT_KEY_LENGTH; // number of octets in input key
    public final int ENC_KEY_LEN; // number of octets in encryption key
    public final int MAC_KEY_LEN; // number of octets in MAC key
    public final String MAC_ALG; // JOSE MAC algorithm name
    public final String JCE_MAC_ALG; // Java (JCE) MAC algorithm name
    public final int T_LEN; // Authentication tag length in bytes

    /**
     * Create immutable configuration containing parameters for the
     * AES-CBC-HMAC-SHA2 encryption scheme.
     *
     * @param INPUT_KEY_LENGTH number of octets in input key
     * @param ENC_KEY_LEN      number of octets in encryption key
     * @param MAC_KEY_LEN      number of octets in MAC key
     * @param MAC_ALG          JOSE MAC algorithm name
     * @param jce_mac_alg      Java (JCE) MAC algorithm name
     * @param t_LEN            Authentication tag length in bytes
     */
    AesConfigurationType(int INPUT_KEY_LENGTH, int ENC_KEY_LEN, int MAC_KEY_LEN, String MAC_ALG, String jce_mac_alg, int t_LEN) {
      this.INPUT_KEY_LENGTH = INPUT_KEY_LENGTH;
      this.ENC_KEY_LEN = ENC_KEY_LEN;
      this.MAC_KEY_LEN = MAC_KEY_LEN;
      this.MAC_ALG = MAC_ALG;
      JCE_MAC_ALG = jce_mac_alg;
      T_LEN = t_LEN;
    }
  }

  @Override
  public String getSecretKeyAlgorithm() {
    return SECRET_KEY_ALGORITHM;
  }
}
