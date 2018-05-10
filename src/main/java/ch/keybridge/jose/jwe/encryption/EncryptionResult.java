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
package ch.keybridge.jose.jwe.encryption;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/01/2018
 */
public class EncryptionResult {

  private final byte[] iv;
  private final byte[] aad;
  private final byte[] ciphertext;
  private final byte[] authTag;

  public EncryptionResult(byte[] iv, byte[] aad, byte[] ciphertext, byte[] authTag) {
    this.iv = iv;
    this.aad = aad;
    this.ciphertext = ciphertext;
    this.authTag = authTag;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getAad() {
    return aad;
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public byte[] getAuthTag() {
    return authTag;
  }
}
