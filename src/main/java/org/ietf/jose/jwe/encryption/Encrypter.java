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

/**
 * An interface for encapsulating encryption and decryption algorithms.
 */
public interface Encrypter {

  /**
   * Generate a valid key for the algorithm
   *
   * @return a valid encryption key
   * @throws GeneralSecurityException in case of failure to unwrap the key or
   *                                  decrypt
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
   * @return A DTO for storing the result of an authenticated encryption (AE)
   *         operation.
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

  /**
   * Get the JCA algorithm name for the secret key used in this encryption
   * scheme
   *
   * @return secret key JCA algorithm name
   */
  String getSecretKeyAlgorithm();
}
