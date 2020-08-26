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
package ch.keybridge.jose;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.util.JsonbUtility;

/**
 * A JWS utility class that provides methods for easy object signing (write) and
 * validation (read).
 * <p>
 * RFC7515 JWS JSON Web Signature, describes producing and handling signed
 * messages
 * <p>
 * JSON Web Signature (JWS) represents content secured with digital signatures
 * or Message Authentication Codes (MACs) using JSON-based data structures.
 * Cryptographic algorithms and identifiers for use with this specification are
 * described in the separate JSON Web Algorithms (JWA) specification and an IANA
 * registry defined by that specification. Related encryption capabilities are
 * described in the separate JSON Web Encryption (JWE) specification.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7516">RFC7516 JWE</a>
 * @author Key Bridge
 * @since v1.0.2 created 2020-08-25
 */
public class JwsUtility {

  /**
   * Build a Json Web Signature compact string: a string which contains the
   * payload and a single signature. Writes and returns the serialiezd object as
   * a compact-form, signed JSON string.
   *
   * @param object the object to be signed; Note that the object _cannot_ be a
   *               primitive String
   * @param key    either a valid AES shared secret key or the recipient's
   *               private key
   * @param keyId  an identifier of the sender to be written as the 'kid' (key
   *               ID) field of the JOSE protected header. Can be null if an
   *               unset 'kid' protected header value is sufficient.
   *
   * @return a Json Web Signature compact string
   * @throws java.io.IOException      on error
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String sign(Object object, Key key, String keyId) throws IOException, GeneralSecurityException {
    String jsonPayload = new JsonbUtility().marshal(object);
    return JwsBuilder.getInstance()
      .withStringPayload(jsonPayload)
      .withKey(key, keyId)
      .sign() // throws IOException, GeneralSecurityException
      .build();
  }

  /**
   * Build a Json Web Signature compact string: a string which contains the
   * payload and a single signature. Writes and returns the serialiezd object as
   * a compact-form, signed JSON string.
   *
   * @param object       the object to be signed; Note that the object _cannot_
   *                     be a primitive String
   * @param sharedSecret a shared secret key
   * @param keyId        an identifier of the sender to be written as the 'kid'
   *                     (key ID) field of the JOSE protected header. Can be
   *                     null if an unset 'kid' protected header value is
   *                     sufficient.
   *
   * @return a Json Web Signature compact string
   * @throws java.io.IOException      on error
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String sign(Object object, String sharedSecret, String keyId) throws IOException, GeneralSecurityException {
    String jsonPayload = new JsonbUtility().marshal(object);
    return JwsBuilder.getInstance()
      .withStringPayload(jsonPayload)
      .withKey(SecretKeyBuilder.fromSharedSecret(sharedSecret), keyId)
      .sign() // throws IOException, GeneralSecurityException
      .build();
  }

  /**
   * Parse and verify a Json Web Signature compact string: a string which
   * contains the payload and a single signature. Reads and returns the
   * deserialized object from a compact-form, signed JSON string.
   *
   * @param <T>            class of the object contained in the message
   * @param compactFormJws a compact-form JWS string
   * @param type           class of the object contained in the message
   * @param key            either a valid AES shared secret key or the
   *                       recipient's private key
   * @return an instance of the class of the object
   * @throws IOException              on deserialization error
   * @throws GeneralSecurityException if the signature does not match
   */
  public static <T> T verify(String compactFormJws, Class<T> type, Key key) throws IOException, GeneralSecurityException {
    JsonWebSignature jws = JsonWebSignature.fromCompactForm(compactFormJws); // throws IOException
    String jsonText = jws.getStringPayload();
    if (!SignatureValidator.isValid(jws, key)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    return new JsonbUtility().unmarshal(jsonText, type);
  }

  /**
   * Parse and verify a Json Web Signature compact string: a string which
   * contains the payload and a single signature. Reads and returns the
   * deserialized object from a compact-form, signed JSON string.
   *
   * @param <T>            class of the object contained in the message
   * @param compactFormJws a compact-form JWS string
   * @param type           class of the object contained in the message
   * @param sharedSecret   a shared secret key
   * @return an instance of the class of the object
   * @throws IOException              on deserialization error
   * @throws GeneralSecurityException if the signature does not match
   */
  public static <T> T verify(String compactFormJws, Class<T> type, String sharedSecret) throws IOException, GeneralSecurityException {
    JsonWebSignature jws = JsonWebSignature.fromCompactForm(compactFormJws); // throws IOException
    String jsonText = jws.getStringPayload();
    if (!SignatureValidator.isValid(jws, SecretKeyBuilder.fromSharedSecret(sharedSecret))) {
      throw new GeneralSecurityException("Invalid signature");
    }
    return new JsonbUtility().unmarshal(jsonText, type);
  }

}
