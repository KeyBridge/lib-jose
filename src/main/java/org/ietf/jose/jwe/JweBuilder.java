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

import ch.keybridge.jose.KeyBridgeJoseProfile;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import org.ietf.jose.JoseProfile;
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwt.JwtClaims;

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
  private static final JoseProfile PROFILE = new KeyBridgeJoseProfile();
  /**
   * The default Jwe EncryptionAlgorithm.
   * <p>
   * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in
   * RFC 7518 Section 5.2.3
   */
  private JweEncryptionAlgorithmType encryptionAlgo = PROFILE.getContentEncAlgo();
  /**
   * Cannot set a default Key Management algorithm at this point because we
   * don't know if a symmetric or asymmetric key will be used for payload
   * encryption.
   */
  private JweKeyAlgorithmType keyMgmtAlgo;
  private JweHeader protectedHeader = new JweHeader();
  private JweHeader unprotectedHeader;
  private byte[] payload;

  /**
   * A Key instance which is used to encrypt the random data encryption key. The
   * key may be either the recipient's PublicKey or a shared SecretKey.
   */
  private Key key;
  /**
   * The corresponding identifier for the encryption key. This value gets
   * written as the 'kid' field in the protected header. Can be null.
   */
  private String keyId;

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
   * Add Jwt claims payload for signing or HMAC calculation
   *
   * @param claims JWT claims to sign and encrypt
   * @return this builder
   */
  public JweBuilder withClaimsPayload(JwtClaims claims) {
    this.payload = claims.toJson().getBytes(StandardCharsets.UTF_8);
    return this;
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
    this.payload = payload.getBytes(StandardCharsets.UTF_8);
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
   * Set the (public) encryption key and key id. The key may be either the
   * recipient's PublicKey or a shared SecretKey.
   *
   * @param key   a Key instance which is used to encrypt the random data
   *              encryption key
   * @param keyId an identifier for the encryption key. This value gets written
   *              as the 'kid' field in the protected header. Can be null.
   * @return this builder
   */
  public JweBuilder withKey(Key key, String keyId) {
    this.key = key;
    this.keyId = keyId;
    if (key instanceof SecretKey) {
      keyMgmtAlgo = resolveKeyManagementAlgorithm((SecretKey) key);
    } else if (keyMgmtAlgo == null) {
      keyMgmtAlgo = PROFILE.getKeyMgmtAlgAsym();
    }
    return this;
  }

  /**
   * Encrypt the payload with the provided recipient's PublicKey
   *
   * @param key   public key
   * @param keyId an identifier for the encryption key. This value gets written
   *              as the 'kid' field in the protected header. Can be null.
   * @return a JweJsonFlattened instance
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public JsonWebEncryption buildJweJsonFlattened(PublicKey key, String keyId) throws IOException, GeneralSecurityException {
    if (keyMgmtAlgo == null) {
      keyMgmtAlgo = PROFILE.getKeyMgmtAlgAsym();
    }
    return JsonWebEncryption.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
                                         protectedHeader, unprotectedHeader, keyId);
  }

  /**
   * Encrypt the payload with the shared SecretKey
   *
   * @param key   secret key; use SecretKeyBuilder if necessary.
   * @param keyId an identifier for the encryption key. This value gets written
   *              as the 'kid' field in the protected header. Can be null.
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

  /**
   * Encrypt the payload with the provided key and converts the JWE instance
   * into a single URL-safe string. Call this method _after_ setting the key.
   *
   * @return a single URL-safe encrypted string
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public String build() throws IOException, GeneralSecurityException {
    return JsonWebEncryption.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
                                         protectedHeader, unprotectedHeader, keyId).toCompactForm();
  }

  /**
   * Encrypt the payload with the provided key and converts the JWE instance
   * into a single URL-safe string. Call this method _after_ setting the key.
   *
   * @return a JWE object, marshaled to JSON
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public String buildJson() throws IOException, GeneralSecurityException {
    return JsonWebEncryption.getInstance(payload, encryptionAlgo, keyMgmtAlgo, key,
                                         protectedHeader, unprotectedHeader, keyId).toJson();
  }

}
