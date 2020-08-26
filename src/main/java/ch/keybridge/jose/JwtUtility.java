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

import org.ietf.jose.JoseProfile;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweDecryptor;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.jwt.JwtClaims;
import org.ietf.jose.jwt.JwtReader;

/**
 * A JWT utility class that provides methods for easy token creation (write) and
 * parting (read).
 * <p>
 * RFC7519 JWT JSON Web Token, describes representation of claims encoded in
 * JSON and protected by JWS (signing) and/or JWE (encryption).
 * <p>
 * JSON Web Token (JWT) is a compact, URL-safe means of representing claims to
 * be transferred between two parties. The claims in a JWT are encoded as a JSON
 * object that is used as the payload of a JSON Web Signature (JWS) structure or
 * as the plaintext of a JSON Web Encryption (JWE) structure, enabling the
 * claims to be digitally signed or integrity protected with a Message
 * Authentication Code (MAC) and/or encrypted.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7519">RFC7519 JWT</a>
 * @author Key Bridge
 * @since v1.0.2 created 2020-08-25
 */
public class JwtUtility {

  /**
   * The Key Bridge default JOSE profile.
   */
  private static final JoseProfile PROFILE = new KeyBridgeJoseProfile();

  /**
   * Create a JSON Web Token signed with a keyed hash (HMAC).
   *
   * @param claims       claims to be asserted by this authorization token. The
   *                     only mandatory field in claims is 'jti'.
   * @param sharedSecret an arbitrary shared secret
   * @param keyId        an identifier for the encryption key. This value gets
   *                     written as the 'kid' field in the protected header. Can
   *                     be null.
   * @return an encoded token that is ready to use as a Bearer token.
   * @throws IOException              in case of failure to serialize the claims
   *                                  to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String writeSignedToken(JwtClaims claims, String sharedSecret, String keyId) throws IOException, GeneralSecurityException {
    final Key key = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    return JwsBuilder.getInstance()
      .withClaimsPayload(claims)
      .sign(key, PROFILE.getSignatureAlgSymmetric(), keyId)
      .build();
  }

  /**
   * Create a JSON Web Token signed with a private key (digital signature).
   *
   * @param claims     claims to be asserted by this authorization token. The
   *                   only mandatory field in claims is 'jti'.
   * @param privateKey a private key used for the digital signature
   * @param keyId      an identifier for the encryption key. This value gets
   *                   written as the 'kid' field in the protected header. Can
   *                   be null.
   * @return an encoded token that is ready to use as a Bearer token.
   * @throws IOException              in case of failure to serialize the claims
   *                                  to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String writeSignedToken(JwtClaims claims, PrivateKey privateKey, String keyId) throws IOException, GeneralSecurityException {
    return JwsBuilder.getInstance()
      .withClaimsPayload(claims)
      .sign(privateKey, PROFILE.getSignatureAlgAsymmetric(), keyId)
      .build();
  }

  /**
   * Parse a signed JSON Web Token signed
   *
   * @param jwt          the raw encoded token
   * @param sharedSecret the shared secret key corresponding that this token was
   *                     signed with
   * @return the JWT claims
   * @throws Exception if the JWT cannot be parsed or if the signature is not
   *                   valid
   */
  public JwtClaims readSignedToken(String jwt, String sharedSecret) throws Exception {
    JsonWebSignature jws = JwtReader.read(jwt).getJsonWebSignature();
    final Key key = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    if (!SignatureValidator.isValid(jws, key)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    return jws.getClaims();
  }

  /**
   * Parse a signed JSON Web Token.
   *
   * @param jwt       the raw encoded token
   * @param publicKey the public key corresponding to the private key that this
   *                  token was signed with
   * @return the JWT claims
   * @throws Exception if the JWT cannot be parsed or if the signature is not
   *                   valid
   */
  public JwtClaims readSignedToken(String jwt, PublicKey publicKey) throws Exception {
    JsonWebSignature jws = JwtReader.read(jwt).getJsonWebSignature();
    if (!SignatureValidator.isValid(jws, publicKey)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    return jws.getClaims();
  }

  /**
   * Create a JSON Web Token encrypted with a shared secret.
   *
   * @param claims       claims to be asserted by this authorization token
   * @param sharedSecret an arbitrary shared secret
   * @param keyId        an identifier for the encryption key. This value gets
   *                     written as the 'kid' field in the protected header. Can
   *                     be null.
   * @return an encoded token that is ready to use as a Bearer token.
   * @throws IOException              in case of failure to serialize the claims
   *                                  to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String writeEncryptedToken(JwtClaims claims, String sharedSecret, String keyId) throws IOException, GeneralSecurityException {
    final SecretKey key = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    return JweBuilder.getInstance()
      .withClaimsPayload(claims)
      .buildJweJsonFlattened(key, keyId)
      .toCompactForm();
  }

  /**
   * Create a JSON Web Token encrypted with a shared secret.
   *
   * @param claims             claims to be asserted by this authorization token
   * @param recipientPublicKey the public key of the recipient; it is used to
   *                           encrypt the message
   * @param recipientKeyId     an identifier for the encryption key. This value
   *                           gets written as the 'kid' field in the protected
   *                           header. Can be null.
   * @return an encoded token that is ready to use as a Bearer token.
   * @throws IOException              in case of failure to serialize the claims
   *                                  to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String writeEncryptedToken(JwtClaims claims, PublicKey recipientPublicKey, String recipientKeyId) throws IOException, GeneralSecurityException {
    return JweBuilder.getInstance()
      .withClaimsPayload(claims)
      .buildJweJsonFlattened(recipientPublicKey, recipientKeyId)
      .toCompactForm();
  }

  /**
   * Parse an encrypted JSON Web Token.
   *
   * @param jwt the raw encoded token
   * @param key the private or shared secret key corresponding to the public (or
   *            shared secret) key that this token was encrypted with the JWT
   *            claims
   * @return the JWT claims
   * @throws Exception if the JWT cannot be parsed or cannot be decrypted
   */
  public JwtClaims parseEncryptedToken(String jwt, Key key) throws Exception {
    JsonWebEncryption jwe = JwtReader.read(jwt).getJsonWebEncryption();
    String json = JweDecryptor.createFor(jwe).decrypt(key).getAsString();
    return JwtClaims.fromJson(json);
  }

  /**
   * Parse an encrypted JSON Web Token.
   *
   * @param jwt          the raw encoded token
   * @param sharedSecret the shared secret key that this token was encrypted
   *                     with
   * @return the JWT claims
   * @throws Exception if the JWT cannot be parsed or cannot be decrypted
   */
  public JwtClaims readEncryptedToken(String jwt, String sharedSecret) throws Exception {
    JsonWebEncryption jwe = JwtReader.read(jwt).getJsonWebEncryption();
    String json = JweDecryptor.createFor(jwe).decrypt(sharedSecret).getAsString();
    return JwtClaims.fromJson(json);
  }

  /**
   * Create a JSON Web Token signed and encrypted with a keyed hash (HMAC).
   *
   * @param claims       claims to be asserted by this authorization token. The
   *                     only mandatory field in claims is 'jti'.
   * @param sharedSecret an arbitrary shared secret
   * @param keyId        an identifier for the encryption key. This value gets
   *                     written as the 'kid' field in the protected header. Can
   *                     be null.
   * @return the JWT claims
   * @throws IOException              in case of failure to serialize the claims
   *                                  to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String writeSignedEncryptedToken(JwtClaims claims, String sharedSecret, String keyId) throws IOException, GeneralSecurityException {
    final SecretKey secretKey = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    JsonWebSignature jws = JwsBuilder.getInstance()
      .withClaimsPayload(claims)
      .sign(secretKey, PROFILE.getSignatureAlgSymmetric(), keyId)
      .buildJsonWebSignature();
    return JweBuilder.getInstance()
      .withStringPayload(jws.toJson())
      .withKey(secretKey, keyId)
      .build();
  }

  /**
   * Create a JSON Web Token signed with a sender private key and encrypted with
   * a recipient public key
   *
   * @param claims             claims to be asserted by this authorization
   *                           token. The only mandatory field in claims is
   *                           'jti'.
   * @param senderPrivateKey   the private key of the sender; it is used to
   *                           digitally sign the message
   * @param recipientPublicKey the public key of the recipient; it is used to
   *                           encrypt the message
   * @param senderKeyId        the sender private key id. identifier of the
   *                           signature key ID to be written as the 'kid' (key
   *                           ID) field of the JWS protected header. Can be
   *                           null if an unset 'kid' protected header value is
   *                           sufficient.
   * @param recipientKeyId     the recipient public key id. an identifier of the
   *                           encryption key to be written as the 'kid' (key
   *                           ID) field of the JWE protected header. Can be
   *                           null if an unset 'kid' protected header value is
   *                           sufficient.
   * @return the JWT claims
   * @throws IOException              in case of failure to serialize the claims
   *                                  to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static String writeSignedEncryptedToken(JwtClaims claims,
                                                 PrivateKey senderPrivateKey,
                                                 PublicKey recipientPublicKey,
                                                 String senderKeyId,
                                                 String recipientKeyId) throws IOException, GeneralSecurityException {
    JsonWebSignature jws = JwsBuilder.getInstance().withClaimsPayload(claims)
      .sign(senderPrivateKey, PROFILE.getSignatureAlgAsymmetric(), senderKeyId)
      .buildJsonWebSignature();
    return JweBuilder.getInstance()
      .withStringPayload(jws.toJson())
      .withKey(recipientPublicKey, recipientKeyId)
      .build();

  }

  /**
   * Parse a JSON Web Token signed and encrypted with a keyed hash (HMAC).
   *
   * @param jwt          the raw encoded token
   * @param sharedSecret an arbitrary shared secret
   * @return the JWT claims
   * @throws GeneralSecurityException if the JWT cannot be decrypted
   * @throws IOException              if the descrypted text fails to parse into
   *                                  a JsonWebSignature
   * @throws Exception                if the JsonWebSignature fails to parse a
   *                                  JwtClaims
   */
  public static JwtClaims readSignedEncryptedToken(String jwt, String sharedSecret) throws GeneralSecurityException, IOException, Exception {
    final SecretKey secretKey = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    JsonWebEncryption jwe = JsonWebEncryption.fromJson(jwt);
    String payload = JweDecryptor.createFor(jwe).decrypt(sharedSecret).getAsString(); // throws GeneralSecurityException
    JsonWebSignature jws = JsonWebSignature.fromJson(payload); // throws IOException
    if (jws.getSignatures().isEmpty()) {
      throw new GeneralSecurityException("A JWS must have at least one signature");
    }
    if (!SignatureValidator.isValid(jws, secretKey)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    return jws.getClaims(); // throws Exception
  }

  /**
   * Parse a JSON Web Token signed with a recipient private key and encrypted
   * with a sender public key
   *
   * @param jwt                 the raw encoded token
   * @param recipientPrivateKey the recipient's private key; it is used to
   *                            decrypt the message
   * @param senderPublicKey     the sender's public key; it is used to validate
   *                            the digital signature
   * @return the JWT claims
   * @throws GeneralSecurityException if the JWT cannot be decrypted
   * @throws IOException              if the descrypted text fails to parse into
   *                                  a JsonWebSignature
   * @throws Exception                if the JsonWebSignature fails to parse a
   *                                  JwtClaims
   */
  public static JwtClaims readSignedEncryptedToken(String jwt,
                                                   PrivateKey recipientPrivateKey,
                                                   PublicKey senderPublicKey) throws GeneralSecurityException, IOException, Exception {
    JsonWebEncryption jwe = JsonWebEncryption.fromJson(jwt);
    String payload = JweDecryptor.createFor(jwe)
      .decrypt(recipientPrivateKey)
      .getAsString();
    JsonWebSignature jws = JsonWebSignature.fromJson(payload);
    if (jws.getSignatures().isEmpty()) {
      throw new GeneralSecurityException("A JWS must have at least one signature");
    }
    if (!SignatureValidator.isValid(jws, senderPublicKey)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    return jws.getClaims(); // throws Exception
  }

}
