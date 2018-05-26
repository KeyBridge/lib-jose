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

/**
 * A DTO for storing the result of an authenticated encryption (AE) operation.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/01/2018
 */
public class EncryptionResult {

  /**
   * Initialization vector: random bytes used to initialise the encryption
   * algorithm.
   */
  private final byte[] iv;
  /**
   * Additional authenticated data: bytes of data that is not encrypted (i.e.
   * remains in plaintext) but its integrity is ensured by the authenticated
   * encryption algorithm.
   */
  private final byte[] aad;
  /**
   * The encrypted data (ciphertext)
   */
  private final byte[] ciphertext;
  /**
   * Authentication tag: a message authentication code used to verify that the
   * ciphertext and additional authenticated data have not been tampered with.
   * This is performed automatically as part of the decryption algorithm.
   */
  private final byte[] authTag;

  public EncryptionResult(byte[] iv, byte[] aad, byte[] ciphertext, byte[] authTag) {
    this.iv = iv;
    this.aad = aad;
    this.ciphertext = ciphertext;
    this.authTag = authTag;
  }

  /**
   * Initialization vector: random bytes used to initialise the encryption
   * algorithm.
   *
   * @return Initialization vector bytes
   */
  public byte[] getIv() {
    return iv;
  }

  /**
   * Additional authenticated data: bytes of data that is not encrypted (i.e.
   * remains in plaintext) but its integrity is ensured by the authenticated
   * encryption algorithm.
   *
   * @return Additional authenticated data bytes
   */
  public byte[] getAad() {
    return aad;
  }

  /**
   * The encrypted data (ciphertext)
   *
   * @return Ciphertext bytes
   */
  public byte[] getCiphertext() {
    return ciphertext;
  }

  /**
   * Authentication tag: a message authentication code used to verify that the
   * ciphertext and additional authenticated data have not been tampered with.
   * This is performed automatically as part of the decryption algorithm.
   *
   * @return Authentication tag bytes
   */
  public byte[] getAuthTag() {
    return authTag;
  }
}
