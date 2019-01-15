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
package org.ietf.jose.jwe;

import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * RFC 7516
 * <p>
 * 7.2. JWE JSON Serialization
 * <p>
 * The JWE JSON Serialization represents encrypted content as a JSON object.
 * This representation is neither optimized for compactness nor URL safe.
 * <p>
 * Two closely related syntaxes are defined for the JWE JSON Serialization: a
 * fully general syntax, with which content can be encrypted to more than one
 * recipient, and a flattened syntax, which is optimized for the
 * single-recipient case.
 *
 * @author Key Bridge
 */
public class JweBuilder {

  /**
   * Default algorithms
   */
  private static final JweEncryptionAlgorithmType CONTENT_ENC_ALGO = JweEncryptionAlgorithmType.A128CBC_HS256;
  private static final JweKeyAlgorithmType KEY_MGMT_ALGO_ASYM = JweKeyAlgorithmType.RSA1_5;

  private JweEncryptionAlgorithmType encryptionAlgo = CONTENT_ENC_ALGO;
  /**
   * Cannot set a default Key Management algorithm at this point because we
   * don't know if a symmetric or asymmetric key will be used for payload
   * encryption.
   */
  private JweKeyAlgorithmType keyMgmtAlgo;
  private JweHeader protectedHeader = new JweHeader();
  private JweHeader unprotectedHeader;
  private byte[] payload;

  private JweBuilder() {
  }

  /**
   * Create a new instance of JweBuilder
   *
   * @return a new JweBuilder instance
   */
  public static JweBuilder getInstance() {
    return new JweBuilder();
  }

  /**
   * Resolve the Key Management algorithm from the SecretKey length (16, 24, or
   * 32). This only applies for symmetric encryption (wrapping) of encryption
   * keys.
   *
   * @param key non-null SecretKey instance
   * @return JweKeyAlgorithmType
   */
  private static JweKeyAlgorithmType resolveKeyManagementAlgorithm(SecretKey key) {
    switch (key.getEncoded().length) {
      case 16:
        return JweKeyAlgorithmType.A128KW;
      case 24:
        return JweKeyAlgorithmType.A192KW;
      case 32:
        return JweKeyAlgorithmType.A256KW;
      default:
        throw new IllegalArgumentException("Key length not 128/192/256 bits.");
    }
  }

  /**
   * Add binary payload for signing or HMAC calculation
   *
   * @param payload data to sign
   * @return this builder
   */
  public JweBuilder withBinaryPayload(byte[] payload) {
    this.payload = payload;
    return this;
  }

  /**
   * Add string payload for signing or HMAC calculation
   *
   * @param payload string to sign
   * @return this builder
   */
  public JweBuilder withStringPayload(String payload) {
    this.payload = payload.getBytes(UTF_8);
    return this;
  }

  /**
   * Add a protected header
   *
   * @param header a JoseCryptoHeader instance
   * @return this builder
   */
  public JweBuilder withProtectedHeader(JweHeader header) {
    protectedHeader = header;
    return this;
  }

  /**
   * Add an unprotected header
   *
   * @param header a JoseCryptoHeader instance
   * @return this builder
   */
  public JweBuilder withUnprotectedHeader(JweHeader header) {
    unprotectedHeader = header;
    return this;
  }

  /**
   * Set the encryption algorithm
   *
   * @param algorithm JweEncryptionAlgorithmType
   * @return this builder
   */
  public JweBuilder withEncryptionAlgorithm(JweEncryptionAlgorithmType algorithm) {
    encryptionAlgo = algorithm;
    return this;
  }

  /**
   * Set the key management algorithm
   *
   * @param algorithm JweKeyAlgorithmType
   * @return this builder
   */
  public JweBuilder withKeyManagementAlgorithm(JweKeyAlgorithmType algorithm) {
    keyMgmtAlgo = algorithm;
    return this;
  }

  /**
   * Encrypt the payload with the provided recipient's PublicKey
   *
   * @param key public key
   * @param keyId an identifier for the encryption key. This value gets written as the 'kid' field in the protected
   *              header.
   *              Can be null.
   * @return a JweJsonFlattened instance
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public JsonWebEncryption buildJweJsonFlattened(PublicKey key, String keyId) throws IOException, GeneralSecurityException {
    if (keyMgmtAlgo == null) {
      keyMgmtAlgo = KEY_MGMT_ALGO_ASYM;
    }
    return JsonWebEncryption.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
        protectedHeader, unprotectedHeader, keyId);
  }

  /**
   * Encrypt the payload with the shared SecretKey
   *
   * @param key secret key; use SecretKeyBuilder if necessary.
   * @param keyId an identifier for the encryption key. This value gets written as the 'kid' field in the protected
   *              header.
   *              Can be null.
   * @return a JweJsonFlattened instance
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public JsonWebEncryption buildJweJsonFlattened(SecretKey key, String keyId) throws IOException, GeneralSecurityException {
    keyMgmtAlgo = resolveKeyManagementAlgorithm(key);
    return JsonWebEncryption.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
        protectedHeader, unprotectedHeader, keyId);
  }

}
