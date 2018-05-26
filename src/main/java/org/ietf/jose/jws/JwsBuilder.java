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
package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.JoseCryptoHeader;
import org.ietf.jose.jwk.JWK;
import org.ietf.jose.util.Base64Utility;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A builder for JSON Web Signature objects.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JwsBuilder {

  private byte[] payload;
  private List<GeneralSignature> signatures = new ArrayList<>();
  private JoseCryptoHeader protectedHeader;
  private JoseCryptoHeader unprotectedHeader;

  private JwsBuilder() {
  }

  /**
   * Create new instance of the builder
   *
   * @return a new builder instance
   */
  public static JwsBuilder getInstance() {
    return new JwsBuilder();
  }

  /**
   * Add binary payload for signing or HMAC calculation
   *
   * @param payload data to sign
   * @return this builder
   */
  public JwsBuilder withBinaryPayload(byte[] payload) {
    this.payload = payload;
    return this;
  }

  /**
   * Add string payload for signing or HMAC calculation
   *
   * @param payload string to sign
   * @return this builder
   */
  public JwsBuilder withStringPayload(String payload) {
    this.payload = payload.getBytes(Base64Utility.DEFAULT_CHARSET);
    return this;
  }

  /**
   * Add a protected header
   *
   * @param header a JoseCryptoHeader instance
   * @return this builder
   */
  public JwsBuilder withProtectedHeader(JoseCryptoHeader header) {
    protectedHeader = header;
    return this;
  }

  /**
   * Add an unprotected header
   *
   * @param header a JoseCryptoHeader instance
   * @return this builder
   */
  public JwsBuilder withUnprotectedHeader(JoseCryptoHeader header) {
    unprotectedHeader = header;
    return this;
  }

  /**
   * Sign using a JWK
   *
   * @param key a JWK instance
   * @return this builder
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(JWK key) throws IOException, GeneralSecurityException {
    signatures.add(GeneralSignature.getInstance(payload, key));
    return this;
  }

  /**
   * Sign using a Key instance and specific algorithm
   *
   * @param key       Key instance
   * @param algorithm a signature algorithm suitable for the provided key
   * @return this builder
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(Key key, JwsAlgorithmType algorithm) throws IOException, GeneralSecurityException {
    if (protectedHeader == null) {
      protectedHeader = new JoseCryptoHeader();
    }
    protectedHeader.setAlg(algorithm.getJoseAlgorithmName());
    signatures.add(GeneralSignature.getInstance(payload, key, protectedHeader, unprotectedHeader));
    return this;
  }

  /**
   * Sign with a keyed hash (HMAC)
   *
   * @param secret    a base64URL-encoded secret
   * @param algorithm a signature algorithm suitable for the provided key
   * @return this builder
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(String secret, JwsAlgorithmType algorithm) throws IOException, GeneralSecurityException {
    SecretKey key = new SecretKeySpec(Base64Utility.fromBase64Url(secret), algorithm.getJavaAlgorithmName());
    return sign(key, algorithm);
  }

  /**
   * Sign with a keyed hash (HMAC)
   *
   * @param secret a base64URL-encoded secret
   * @return this builder
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(String secret) throws IOException, GeneralSecurityException {
    byte[] keyBytes = Base64Utility.fromBase64Url(secret);
    JwsAlgorithmType algorithm;
    switch (keyBytes.length) {
      case 32:
        algorithm = JwsAlgorithmType.HS256;
        break;
      case 48:
        algorithm = JwsAlgorithmType.HS384;
        break;
      case 64:
        algorithm = JwsAlgorithmType.HS512;
        break;
      default:
        throw new IllegalArgumentException("Unsupported key length: " + keyBytes.length);
    }
    SecretKey key = new SecretKeySpec(keyBytes, algorithm.getJavaAlgorithmName());
    return sign(key, algorithm);
  }

  /**
   * Build a JWS instance: A JWS object with one or more signatures
   *
   * @return a JWS instance
   */
  public JWS buildJson() {
    return new JWS(payload, signatures);
  }

  /**
   * Build a FlattendedSignature instance: A JWS object with a single signature.
   *
   * @return a FlattendedSignature instance
   */
  public FlattendedSignature buildJsonFlattened() {
    return new JWS(payload, signatures).toFlattened();
  }

  /**
   * Build a JWS compact string: a string which contains the payload and a
   * single signature.
   *
   * @return a JWS compact string
   */
  public String buildCompact() throws IOException {
    return buildJsonFlattened().getCompactForm();
  }
}
