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
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweHeader;
import org.ietf.jose.jwe.JweJsonFlattened;
import org.ietf.jose.jws.FlattenedJsonSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.util.JsonMarshaller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * lib-jose – Javascript Object Signing and Encryption.
 *
 * This class is the entry point to the library. Provides easy access to the main components:
 * <ul>
 *   <li>Javascript Web Signatures (JWS)</li>
 *   <li>Javascript Web Encryption (JWE)</li>
 *   <li>Javascript Web Tokens (JWT)</li>
 *   <li>Javascript Web signing and encryption (combination of JWS and JWE)</li>
 * </ul>
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
     * @return
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
     * </pre> See RFC 7516 Section 7.1 for more information about the JWE Compact
     * Serialization.
     *
     * @param compactForm a valid compact JWE string
     * @return non-null JWE instance
     * @throws IllegalArgumentException if the provided input is not a valid
     *                                  compact JWE string
     */
    public static JweJsonFlattened fromCompactForm(String compactForm) throws IOException {
      return JweJsonFlattened.fromCompactForm(compactForm);
    }

    /**
     * Deserialize an object from JSON
     *
     * @param json json string representing the object
     * @return a non-null object instance
     */
    public static JweJsonFlattened fromJson(String json) throws IOException {
      return JsonMarshaller.fromJson(json, JweJsonFlattened.class);
    }

    public static byte[] decryptBinary(JweJsonFlattened jwe, Key key) throws GeneralSecurityException {
      return jwe.decryptPayload(key);
    }

    /**
     * Decrypt the payload as string
     *
     * @param jwe valid JweJsonFlattened instance
     * @param key key used to encrypt the payload
     * @return decrypted plaintext
     * @throws GeneralSecurityException
     */
    public static String decryptString(JweJsonFlattened jwe, Key key) throws GeneralSecurityException {
      return jwe.decryptAsString(key);
    }

    /**
     * Verify if the object has not been tampered with. Check the additional authenticated data
     * and attempts to decrypt.
     *
     * @param jwe JWE instance
     * @param key key used to encrypt the payload
     * @return true if the additional authenticated data validated and payload decrypted successfully
     * @throws GeneralSecurityException
     */
    public static boolean verify(JweJsonFlattened jwe, Key key) throws GeneralSecurityException {
      return jwe.decryptPayload(key) == null;
    }
  }

  /**
   * Build, verify and decode Javascript Web Signature objects.
   */
  public static class JWS {

    /**
     * Create new JWS object from scratch.
     *
     * @return
     */
    public static JwsBuilder newBuilder() {
      return JwsBuilder.getInstance();
    }

    /**
     * 3.1.  JWS Compact Serialization Overview
     * <p>
     * In the JWS Compact Serialization, no JWS Unprotected Header is used.
     * In this case, the JOSE Header and the JWS Protected Header are the
     * same.
     * <p>
     * In the JWS Compact Serialization, a JWS is represented as the
     * concatenation:
     * <pre>
     *       BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
     *       BASE64URL(JWS Payload) || ’.’ ||
     *       BASE64URL(JWS Signature)
     *       </pre>
     * See RFC 7515 Section 7.1 for more information about the JWS Compact
     * Serialization.
     *
     * @param compactForm a valid compact JWS string
     * @return non-null JWE instance
     * @throws IOException
     * @throws IllegalArgumentException if the provided input is not a valid
     *                                  compact JWS string
     */
    public static FlattenedJsonSignature fromCompactForm(String compactForm) throws IOException {
      return FlattenedJsonSignature.fromCompactForm(compactForm);
    }

    /**
     * Deserialize an object from JSON
     *
     * @param json json string representing the object
     * @return a non-null object instance
     */
    public static FlattenedJsonSignature fromJson(String json) throws IOException {
      return JsonMarshaller.fromJson(json, FlattenedJsonSignature.class);
    }

    /**
     * Validate signature using a Key instance
     *
     * @param jws a valid FlattendedJsonSignature instance
     * @param key       a Key instance
     * @return true if signature is valid
     * @throws IOException              in case of failure to serialise the
     *                                  protected header to JSON
     * @throws GeneralSecurityException in case of failure to validate the
     *                                  signature
     */
    public static boolean verify(FlattenedJsonSignature jws, Key key) throws IOException, GeneralSecurityException {
      return SignatureValidator.isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws
          .getSignatureBytes());
    }
  }

  /**
   * Utility class for convenient object signing and encryption in a single step.
   */
  public static class SignAndEncrypt {
    /**
     * Reads string as a JWE flattened object that has as its payload a JWS
     * Flattened object, which in turn contains the end payload object of type T.
     * Validates digital signature using the public key of the sender and uses the
     * recipients private key to decrypt.
     *
     * @param json        JSON string which is valid JWE flattened JSON
     * @param type        class of object contained.
     * @param receiverKey recipient's private key; it is used to decrypt message
     * @param senderKey   sender's public key; it is used to validate the digital
     *                    signature
     * @param <T>         class of the object contained in the message
     * @return decrypted object. null is returned in the case of invalid
     * signature, failure to decrypt or deserialise JSON.
     */
    public static <T> T read(String json, Class<T> type, PrivateKey receiverKey, PublicKey senderKey) {
      try {
        JweJsonFlattened jwe = JsonMarshaller.fromJson(json, JweJsonFlattened.class);
        String payload = jwe.decryptAsString(receiverKey);

        FlattenedJsonSignature jws = JsonMarshaller.fromJson(payload, FlattenedJsonSignature.class);

        /**
         * The payload is rejected if the digital signature cannot be validated.
         */
        boolean signatureValid = SignatureValidator.isValid(jws, senderKey);
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
     * Flattened object, which in turn contains the end payload object of type T.
     * Decrypts message and validates the keyed message authetication token using
     * the shared secret.
     *
     * @param json                   JSON string which is valid JWE flattened JSON
     * @param type                   class of object contained.
     * @param base64UrlEncodedSecret base64URL-encoded bytes of the shared secret
     * @param <T>                    class of the object contained in the message
     * @return decrypted object. null is returned in the case of invalid
     * signature, failure to decrypt or deserialise JSON.
     */
    public static <T> T read(String json, Class<T> type, String base64UrlEncodedSecret) {
      try {
        JweJsonFlattened jwe = JsonMarshaller.fromJson(json, JweJsonFlattened.class);
        String payload = jwe.decryptAsString(JweBuilder.createSecretKey(base64UrlEncodedSecret));

        /**
         * The payload is rejected if the digital signature cannot be validated.
         */
        FlattenedJsonSignature jws = JsonMarshaller.fromJson(payload, FlattenedJsonSignature.class);

        boolean signatureValid = SignatureValidator.isValid(jws, base64UrlEncodedSecret);
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
     * @param signatureKeyId   an identifier of the signature key ID to be written as the
     *                         'kid' (key ID) field of the JWS protected header.
     *                         Can be null if an unset 'kid' protected header
     *                         value is sufficient.
     * @return a valid JSON string if the operation is successful; null in case of
     * failure
     */
    public static String write(Object object, PrivateKey senderPrivateKey, PublicKey publicKey, String signatureKeyId) {
      try {
        String jsonPayload = JsonMarshaller.toJson(object);

        FlattenedJsonSignature jws = JwsBuilder.getInstance()
            .withStringPayload(jsonPayload)
            .sign(senderPrivateKey, JwsAlgorithmType.RS256, signatureKeyId)
            .buildJsonFlattened();

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
     * @param object                 the object to be signed and encrypted
     * @param base64UrlEncodedSecret base64URL-encoded bytes of the shared secret;
     *                               it is used to generate a keyed message
     *                               authentication code (HMAC) and to encrypt the
     *                               message.
     * @param senderId               an identifier of the sender to be written as
     *                               the 'kid' (key ID) field of the JOSE
     *                               protected header. Can be null if an unset
     *                               'kid' protected header value is sufficient.
     * @return a valid JSON string if the operation is successful; null in case of
     * failure
     */
    public static String write(Object object, String base64UrlEncodedSecret, String senderId) {
      try {
        String jsonPayload = JsonMarshaller.toJson(object);

        FlattenedJsonSignature jws = JwsBuilder.getInstance()
            .withStringPayload(jsonPayload)
            .sign(base64UrlEncodedSecret, JwsAlgorithmType.HS256, senderId)
            .buildJsonFlattened();

        JweHeader jweHeader = new JweHeader();
        jweHeader.setKid(senderId);

        return JweBuilder.getInstance()
            .withStringPayload(jws.toJson())
            .withProtectedHeader(jweHeader)
            .buildJweJsonFlattened(base64UrlEncodedSecret)
            .toJson();
      } catch (IOException | GeneralSecurityException e) {
        LOG.log(Level.SEVERE, null, e);
      }
      return null;
    }
  }
}
