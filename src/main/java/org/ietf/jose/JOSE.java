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
package org.ietf.jose;

import org.ietf.jose.jws.JwsHeader;
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweHeader;
import org.ietf.jose.jwe.JweJsonFlattened;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.FlattendedJsonSignature;
import org.ietf.jose.util.JsonMarshaller;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for convenient object signing and encryption as per the SAS-ESC
 * Protocol.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JOSE {

  private final static Logger LOG = Logger.getLogger(JOSE.class.getCanonicalName());

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
   *         signature, failure to decrypt or deserialise JSON.
   */
  public static <T> T read(String json, Class<T> type, PrivateKey receiverKey, PublicKey senderKey) {
    try {
      JweJsonFlattened jwe = JsonMarshaller.fromJson(json, JweJsonFlattened.class);
      String payload = jwe.decryptAsString(receiverKey);

      FlattendedJsonSignature jws = JsonMarshaller.fromJson(payload, FlattendedJsonSignature.class);

      /**
       * The payload is rejected if the digital signature cannot be validated.
       */
      boolean signatureValid = jws.getJwsSignature().isValidSignature(jws.getPayload(), senderKey);
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
   *         signature, failure to decrypt or deserialise JSON.
   */
  public static <T> T read(String json, Class<T> type, String base64UrlEncodedSecret) {
    try {
      JweJsonFlattened jwe = JsonMarshaller.fromJson(json, JweJsonFlattened.class);
      String payload = jwe.decryptAsString(JweBuilder.createSecretKey(base64UrlEncodedSecret));

      /**
       * The payload is rejected if the digital signature cannot be validated.
       */
      FlattendedJsonSignature jws = JsonMarshaller.fromJson(payload, FlattendedJsonSignature.class);

      boolean signatureValid = jws.getJwsSignature().isValidSignature(jws.getPayload(), base64UrlEncodedSecret);
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
   * @param senderId         an identifier of the sender to be written as the
   *                         'kid' (key ID) field of the JOSE protected header.
   *                         Can be null if an unset 'kid' protected header
   *                         value is sufficient.
   * @return a valid JSON string if the operation is successful; null in case of
   *         failure
   */
  public static String write(Object object, PrivateKey senderPrivateKey, PublicKey publicKey, String senderId) {
    try {
      String jsonPayload = JsonMarshaller.toJson(object);

      JwsHeader jwsHeader = new JwsHeader();
      jwsHeader.setKid(senderId);

      FlattendedJsonSignature jws = JwsBuilder.getInstance()
        .withStringPayload(jsonPayload)
        .withProtectedHeader(jwsHeader)
        .sign(senderPrivateKey, JwsAlgorithmType.RS256)
        .buildJsonFlattened();

      JweHeader jweHeader = new JweHeader();
      jweHeader.setKid(senderId);

      return JweBuilder.getInstance()
        .withStringPayload(jws.toJson())
        .withProtectedHeader(jweHeader)
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
   *         failure
   */
  public static String write(Object object, String base64UrlEncodedSecret, String senderId) {
    try {
      String jsonPayload = JsonMarshaller.toJson(object);

      JwsHeader jwsHeader = new JwsHeader();
      jwsHeader.setKid(senderId);

      FlattendedJsonSignature jws = JwsBuilder.getInstance()
        .withStringPayload(jsonPayload)
        .withProtectedHeader(jwsHeader)
        .sign(base64UrlEncodedSecret)
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
