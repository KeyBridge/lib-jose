/*
 * Copyright 2020 Key Bridge. All rights reserved. Use is subject to license
 * terms.
 *
 * This software code is protected by Copyrights and remains the property of
 * Key Bridge and its suppliers, if any. Key Bridge reserves all rights in and to
 * Copyrights and no license is granted under Copyrights in this Software
 * License Agreement.
 *
 * Key Bridge generally licenses Copyrights for commercialization pursuant to
 * the terms of either a Standard Software Source Code License Agreement or a
 * Standard Product License Agreement. A copy of either Agreement can be
 * obtained upon request by sending an email to info@keybridgewireless.com.
 *
 * All information contained herein is the property of Key Bridge and its
 * suppliers, if any. The intellectual and technical concepts contained herein
 * are proprietary.
 */
package ch.keybridge.lib.jose;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.SecretKey;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweDecryptor;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.util.JsonbUtility;

/**
 * A JWE utility class that provides methods for easy object encryption (write)
 * and decryption (read).
 * <p>
 * RFC7516 JWE JSON Web Encryption, describes producting and handling encrypted
 * messages.
 * <p>
 * JSON Web Encryption (JWE) represents encrypted content using JSON-based data
 * structures. Cryptographic algorithms and identifiers for use with this
 * specification are described in the separate JSON Web Algorithms (JWA)
 * specification and IANA registries defined by that specification. Related
 * digital signature and Message Authentication Code (MAC) capabilities are
 * described in the separate JSON Web Signature (JWS) specification.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7516">RFC7516 JWE</a>
 * @author Key Bridge
 * @since v1.0.2 created 2020-08-25
 */
public class JweUtility {

  /**
   * Converts a JWE compact serialization string into a JWE instance.
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
   * @param <T>            class of the object contained in the message
   * @param compactFormJwe a compact-form JWE string
   * @param type           class of the object contained in the message
   * @param key            either a valid AES shared secret key or the
   *                       recipient's private key
   * @return instance of the specified object class
   * @throws IOException              on deserialization error if the string
   *                                  cannot be parsed to a JWE intance
   * @throws GeneralSecurityException if the key fails to decrypt the string
   */
  public static <T> T decrypt(String compactFormJwe, Class<T> type, Key key) throws IOException, GeneralSecurityException {
    JsonWebEncryption jwe = JsonWebEncryption.fromCompactForm(compactFormJwe); // throws IOException
    String jsonPayload = JweDecryptor.createFor(jwe)
      .decrypt(key) // throws GeneralSecurityException
      .getAsString();
    return new JsonbUtility().unmarshal(jsonPayload, type);
  }

  /**
   * Converts a JWE compact serialization string into a JWE instance.
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
   * @param <T>            class of the object contained in the message
   * @param compactFormJwe a compact-form JWE string
   * @param type           class of the object contained in the message
   * @param sharedSecret   a shared secret key
   * @return instance of the specified object class
   * @throws IOException              on deserialization error if the string
   *                                  cannot be parsed to a JWE intance
   * @throws GeneralSecurityException if the key fails to decrypt the string
   */
  public static <T> T decrypt(String compactFormJwe, Class<T> type, String sharedSecret) throws IOException, GeneralSecurityException {
    JsonWebEncryption jwe = JsonWebEncryption.fromCompactForm(compactFormJwe); // throws IOException
    String jsonPayload = JweDecryptor.createFor(jwe)
      .decrypt(sharedSecret) // throws GeneralSecurityException
      .getAsString();
    return new JsonbUtility().unmarshal(jsonPayload, type);
  }

  /**
   * Write object as an encrypted JSON string.
   *
   * @param object the object to serialize
   * @param key    either a valid AES shared secret key or the recipient's
   *               public key
   * @param keyId  an identifier of the sender to be written as the 'kid' (key
   *               ID) field of the JOSE protected header. Can be null if an
   *               unset 'kid' protected header value is sufficient.
   * @return a compact-form JWE string
   * @throws IOException              in case of failure to serialize the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public static String encrypt(Object object, Key key, String keyId) throws IOException, GeneralSecurityException {
    String jsonPayload = new JsonbUtility().marshal(object);
    return JweBuilder.getInstance()
      .withStringPayload(jsonPayload)
      .withKey(key, keyId)
      .build(); // throws IOException, GeneralSecurityException
  }

  /**
   * Write object as an encrypted JSON string.
   *
   * @param object       the object to serialize
   * @param sharedSecret a shared secret key
   * @param keyId        an identifier of the sender to be written as the 'kid'
   *                     (key ID) field of the JOSE protected header. Can be
   *                     null if an unset 'kid' protected header value is
   *                     sufficient.
   * @return a compact-form JWE string
   * @throws IOException              in case of failure to serialize the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to encrypt
   */
  public static String encrypt(Object object, String sharedSecret, String keyId) throws IOException, GeneralSecurityException {
    String jsonPayload = new JsonbUtility().marshal(object);
    SecretKey secretKey = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    return JweBuilder.getInstance()
      .withStringPayload(jsonPayload)
      .withKey(secretKey, keyId)
      .build(); // throws IOException, GeneralSecurityException
  }

}
