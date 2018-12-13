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
package ch.keybridge.lib.jose;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweDecryptor;
import org.ietf.jose.jwe.JweHeader;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.Signature;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.util.JsonMarshaller;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * lib-jose – Javascript Object Signing and Encryption.
 * <p>
 * This class is the entry point to the library. Provides easy access to the
 * main components:
 * <ul>
 * <li>Javascript Web Signatures (JWS)</li>
 * <li>Javascript Web Encryption (JWE)</li>
 * <li>Javascript Web Tokens (JWT)</li>
 * <li>Javascript Web signing and encryption (combination of JWS and JWE)</li>
 * </ul>
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JOSE {

  private final static Logger LOG = Logger.getLogger(JOSE.class.getCanonicalName());

  /**
   * Build, verify and decode Javascript Web Encryption objects.
   */
  public static class JWE {

    /**
     * Create new JWE object from scratch.
     *
     * @return a new JWE object
     */
    public static JweBuilder newBuilder() {
      return JweBuilder.getInstance();
    }

    /**
     * Converts a JWE compact serialization string into a JWE instance
     * <p>
     * In the JWE Compact Serialization, no JWE Shared Unprotected Header or JWE
     * Per-Recipient Unprotected Header are used. In this case, the JOSE Header
     * and the JWE Protected Header are the same. In the JWE Compact
     * Serialization, a JWE is represented as the concatenation:
     * <pre>
     * BASE64URL(UTF8(JWE Protected Header)) || ’.’ ||
     * BASE64URL(JWE Encrypted Key) || ’.’ ||
     * BASE64URL(JWE Initialization Vector) || ’.’ ||
     * BASE64URL(JWE Ciphertext) || ’.’ ||
     * BASE64URL(JWE Authentication Tag)
     * </pre> See RFC 7516 Section 7.1 for more information about the JWE
     * Compact Serialization.
     *
     * @param compactForm a valid compact JWE string
     * @return non-null JWE instance
     * @throws IllegalArgumentException if the provided input is not a valid
     *                                  compact JWE string
     * @throws java.io.IOException      on serialization error
     */
    public static JsonWebEncryption fromCompactForm(String compactForm) throws IOException {
      return JsonWebEncryption.fromCompactForm(compactForm);
    }

    /**
     * Deserialize an object from JSON
     *
     * @param json json string representing the object
     * @return a non-null object instance
     * @throws java.io.IOException on serialization error
     */
    public static JsonWebEncryption fromJson(String json) throws IOException {
      return JsonMarshaller.fromJson(json, JsonWebEncryption.class);
    }

    public static JweDecryptor decrypt(JsonWebEncryption jwe) {
      return JweDecryptor.createFor(jwe);
    }

  }

  /**
   * Build, verify and decode Javascript Web Signature objects.
   */
  public static class JWS {

    /**
     * Create new JWS object from scratch.
     *
     * @return a new JWS object
     */
    public static JwsBuilder newBuilder() {
      return JwsBuilder.getInstance();
    }

    /**
     * 3.1. JWS Compact Serialization Overview
     * <p>
     * In the JWS Compact Serialization, no JWS Unprotected Header is used. In
     * this case, the JOSE Header and the JWS Protected Header are the same.
     * <p>
     * In the JWS Compact Serialization, a JWS is represented as the
     * concatenation:
     * <pre>
     *       BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
     *       BASE64URL(JWS Payload) || ’.’ ||
     *       BASE64URL(JWS Signature)
     * </pre> See RFC 7515 Section 7.1 for more information about the JWS
     * Compact Serialization.
     *
     * @param compactForm a valid compact JWS string
     * @return non-null JWE instance
     * @throws IOException              on serialization error
     * @throws IllegalArgumentException if the provided input is not a valid
     *                                  compact JWS string
     */
    public static JsonWebSignature fromCompactForm(String compactForm) throws IOException {
      return JsonWebSignature.fromCompactForm(compactForm);
    }

    /**
     * Deserialize an object from JSON
     *
     * @param json json string representing the object
     * @return a non-null object instance
     * @throws java.io.IOException on serialization error
     */
    public static JsonWebSignature fromJson(String json) throws IOException {
      return JsonMarshaller.fromJson(json, JsonWebSignature.class);
    }

    /**
     * Validate signature using a Key instance
     *
     * @param signature a valid Signature instance
     * @param key       a Key instance
     * @return true if signature is valid
     */
    public static boolean verify(Signature signature, SecretKey key) {
      return SignatureValidator.isValid(signature, key);
    }
  }

  /**
   * Utility class for convenient object signing and encryption in a single
   * step.
   */
  public static class SignAndEncrypt {

    /**
     * Reads string as a JWE flattened object that has as its payload a JWS
     * Flattened object, which in turn contains the end payload object of type
     * T. Validates digital signature using the public key of the sender and
     * uses the recipients private key to decrypt.
     *
     * @param json        JSON string which is valid JWE flattened JSON
     * @param type        class of object contained.
     * @param receiverKey the recipient's private key; it is used to decrypt the
     *                    message
     * @param senderKey   the sender's public key; it is used to validate the
     *                    digital signature
     * @param <T>         class of the object contained in the message
     * @return decrypted object. null is returned in the case of invalid
     * signature, failure to decrypt or deserialise JSON.
     */
    public static <T> T read(String json, Class<T> type, PrivateKey receiverKey, PublicKey senderKey) {
      try {
        JsonWebEncryption jwe = JsonWebEncryption.fromJson(json);
        String payload = JweDecryptor.createFor(jwe)
            .decrypt(receiverKey)
            .getAsString();

        JsonWebSignature jws = JsonWebSignature.fromJson(payload);
        List<Signature> signatures = jws.getSignatures();
        if (signatures.isEmpty()) {
          throw new IllegalArgumentException("A JWS must have at least one signature");
        }
        if (signatures.size() > 1) {
          LOG.log(Level.WARNING, "JWS {1} signatures instead of the expected 1. Validating only the first signature"
              + ".", new Object[]{signatures.size()});
        }
        /**
         * The payload is rejected if the digital signature cannot be validated.
         */
        boolean signatureValid = SignatureValidator.isValid(signatures.get(0), senderKey);
        if (!signatureValid) {
          return null;
        }
        String mainPayload = jws.getStringPayload();
        return JsonMarshaller.fromJson(mainPayload, type);
      } catch (IOException | GeneralSecurityException e) {
        LOG.log(Level.SEVERE, null, e);
      }
      return null;
    }

    /**
     * Reads string as a JWE flattened object that has as its payload a JWS
     * Flattened object, which in turn contains the end payload object of type
     * T. Decrypts message and validates the keyed message authetication token
     * using the shared secret.
     *
     * @param json      JSON string which is valid JWE flattened
     *                  JSON
     * @param type      class of object contained.
     * @param secretKey a valid AES secret key
     * @param <T>       class of the object contained in the
     *                  message
     * @return decrypted object. null is returned in the case of invalid
     * signature, failure to decrypt or deserialise JSON.
     */
    public static <T> T read(String json, Class<T> type, SecretKey secretKey) {
      try {
        JsonWebEncryption jwe = JsonWebEncryption.fromJson(json);
        String payload = JweDecryptor.createFor(jwe)
            .decrypt(secretKey)
            .getAsString();

        /**
         * The payload is rejected if the digital signature cannot be validated.
         */
        JsonWebSignature jws = JsonWebSignature.fromJson(payload);
        List<Signature> signatures = jws.getSignatures();
        if (signatures.isEmpty()) {
          throw new IllegalArgumentException("A JWS must have at least one signature");
        }
        if (signatures.size() > 1) {
          LOG.log(Level.WARNING, "JWS {0} signatures instead of the expected 1. Validating only the first signature"
              + ".", new Object[]{signatures.size()});
        }
        boolean signatureValid = SignatureValidator.isValid(signatures.get(0), secretKey);
        if (!signatureValid) {
          return null;
        }
        String mainPayload = jws.getStringPayload();
        return JsonMarshaller.fromJson(mainPayload, type);
      } catch (IOException | GeneralSecurityException e) {
        LOG.log(Level.SEVERE, null, e);
      }
      return null;
    }

    /**
     * Write object as a signed and encrypted JSON string.
     *
     * @param object           the object to be signed and encrypted
     * @param senderPrivateKey the private key of the sender; it is used to
     *                         digitally sign the message
     * @param publicKey        the public key of the recipient; it is used to
     *                         encrypt the message
     * @param signatureKeyId   an identifier of the signature key ID to be
     *                         written as the 'kid' (key ID) field of the JWS
     *                         protected header. Can be null if an unset 'kid'
     *                         protected header value is sufficient.
     * @return a valid JSON string if the operation is successful; null in case
     * of failure
     */
    public static String write(Object object, PrivateKey senderPrivateKey, PublicKey publicKey, String signatureKeyId) {
      try {
        String jsonPayload = JsonMarshaller.toJson(object);

        JsonWebSignature jws = JwsBuilder.getInstance()
            .withStringPayload(jsonPayload)
            .sign(senderPrivateKey, JwsAlgorithmType.RS256, signatureKeyId)
            .buildJsonWebSignature();

        return JweBuilder.getInstance()
            .withStringPayload(jws.toJson())
            .buildJweJsonFlattened(publicKey)
            .toJson();
      } catch (IOException | GeneralSecurityException e) {
        LOG.log(Level.SEVERE, null, e);
      }
      return null;
    }

    /**
     * Write object as a signed and encrypted JSON string.
     *
     * @param object    the object to be signed and encrypted
     * @param secretKey valid AES secret key
     * @param senderId  an identifier of the sender to be written
     *                  as the 'kid' (key ID) field of the JOSE
     *                  protected header. Can be null if an unset
     *                  'kid' protected header value is sufficient.
     * @return a valid JSON string if the operation is successful; null in case
     * of failure
     */
    public static String write(Object object, SecretKey secretKey, String senderId) {
      try {
        String jsonPayload = JsonMarshaller.toJson(object);

        JsonWebSignature jws = JwsBuilder.getInstance()
            .withStringPayload(jsonPayload)
            .sign(secretKey, JwsAlgorithmType.HS256, senderId)
            .buildJsonWebSignature();

        JweHeader jweHeader = new JweHeader();
        jweHeader.setKid(senderId);

        return JweBuilder.getInstance()
            .withStringPayload(jws.toJson())
            .withProtectedHeader(jweHeader)
            .buildJweJsonFlattened(secretKey)
            .toJson();
      } catch (IOException | GeneralSecurityException e) {
        LOG.log(Level.SEVERE, null, e);
      }
      return null;
    }
  }
}
