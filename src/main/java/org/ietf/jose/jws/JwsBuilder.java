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
import org.ietf.jose.jwk.JsonWebKey;
import org.ietf.jose.util.Base64Utility;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

/**
 * A builder for JSON Web Signature objects.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JwsBuilder {

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
  public Signable withBinaryPayload(byte[] payload) {
    return Signable.getInstance(payload);
  }

  /**
   * Add string payload for signing or HMAC calculation
   *
   * @param payload string to sign
   * @return this builder
   */
  public Signable withStringPayload(String payload) {
    byte[] payloadBytes = payload.getBytes(Base64Utility.DEFAULT_CHARSET);
    return Signable.getInstance(payloadBytes);
  }

  public static class Signable {

    /**
     * The JWS payload.
     */
    private byte[] payload;
    /**
     * The "signature" member MUST be present and contain the value
     * BASE64URL(JWS Signature).
     */
    private final List<Signature> signatures = new ArrayList<>();

    /**
     * The "protected" member MUST be present and contain the value
     * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected Header value
     * is non-empty; otherwise, it MUST be absent. These Header Parameter values
     * are integrity protected.
     */
    private JwsHeader protectedHeader;
    /**
     * The "header" member MUST be present and contain the value JWS Unprotected
     * Header when the JWS Unprotected Header value is non- empty; otherwise, it
     * MUST be absent. This value is represented as an unencoded JSON object,
     * rather than as a string. These Header Parameter values are not integrity
     * protected.
     */
    private JwsHeader header;

    private Signable() {
    }

    public static Signable getInstance(byte[] payload) {
      Signable builder = new Signable();
      builder.payload = payload;
      return builder;
    }

    /**
     * Add a protected header
     *
     * @param header a JwsHeader instance
     * @return this builder
     */
    public Signable withProtectedHeader(JwsHeader header) {
      this.protectedHeader = header;
      return this;
    }

    /**
     * Add an unprotected header
     *
     * @param header a JwsHeader instance
     * @return this builder
     */
    public Signable withHeader(JwsHeader header) {
      this.header = header;
      return this;
    }

    /**
     * Sign using a JWK
     *
     * @param key       a JWK instance
     * @param algorithm the JwsAlgorithmType
     * @return this builder
     * @throws IOException              in case of failure to serialise the
     *                                  protected header to JSON
     * @throws GeneralSecurityException in case of failure to sign
     */
    public Signable sign(JsonWebKey key, JwsAlgorithmType algorithm) throws IOException, GeneralSecurityException {
      this.signatures.add(Signature.getInstance(payload, key, algorithm));
      return this;
    }

    /**
     * Sign using a Key instance and specific algorithm
     *
     * @param key       Key instance (either a PrivateKey or a SecretKey)
     * @param algorithm a signature algorithm suitable for the provided key
     * @param keyId     a key ID which is put in the protected header's 'kid'
     *                  field
     * @return this builder
     * @throws IOException              in case of failure to serialise the
     *                                  protected header to JSON
     * @throws GeneralSecurityException in case of failure to sign
     */
    public Signable sign(Key key, JwsAlgorithmType algorithm, String keyId) throws IOException,
      GeneralSecurityException {
      if (protectedHeader == null) {
        this.protectedHeader = new JwsHeader();
      }
      this.protectedHeader.setKid(keyId);
      this.protectedHeader.setAlg(algorithm.getJoseAlgorithmName());
      this.signatures.add(Signature.getInstance(payload, key, protectedHeader, header));
      return this;
    }

    /**
     * Build a GeneralJsonSignature instance: A GeneralJsonSignature object with
     * one or more signatures
     *
     * @return a GeneralJsonSignature instance
     */
    public JsonWebSignature buildJsonWebSignature() {
      return new JsonWebSignature(payload, signatures);
    }

    /**
     * Build a GeneralJsonSignature compact string: a string which contains the
     * payload and a single signature.
     *
     * @return a GeneralJsonSignature compact string
     * @throws java.io.IOException on error
     */
    public String buildCompact() throws IOException {
      return buildJsonWebSignature().getCompactForm();
    }
  }
}
