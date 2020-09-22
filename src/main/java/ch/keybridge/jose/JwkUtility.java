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

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;
import org.ietf.jose.jwk.JwkSet;
import org.ietf.jose.jwk.key.EllipticCurvePublicJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;

/**
 * RFC 7517 JSON Web Key (JWK)
 * <p>
 * A JWK utility class that provides methods for easy object generation and
 * parsing.
 * <p>
 * A JWK is a JSON object that represents a cryptographic key. A JWK Set is a
 * JSON object that represents a set of JWKs.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @author Key Bridge
 * @since v1.3.0 created 2020-09-21
 */
public class JwkUtility {

  private static final Logger LOG = Logger.getLogger(SetBuilder.class.getName());

  /**
   * Get a new JWK set builder.
   *
   * @return a new JWK set builder.
   */
  public static JwkUtility.SetBuilder getSetBuilder() {
    return new SetBuilder();
  }

  /**
   * An internal builder class.
   */
  public static class SetBuilder {

    /**
     * The internal JWK set instance.
     */
    private final JwkSet jwkSet = new JwkSet();

    /**
     * Add a public key to the JWK set.
     *
     * @param publicKey the public key
     * @param keyId     the key id (optional)
     * @return the current set builder instance
     */
    public SetBuilder withPublicKey(PublicKey publicKey, String keyId) {
      if (publicKey instanceof RSAPublicKey) {
        jwkSet.addKey(RsaPublicJwk.getInstance((RSAPublicKey) publicKey, keyId));
      } else if (publicKey instanceof ECPublicKey) {
        LOG.fine("EllipticCurve keys are only partially supported.");
        jwkSet.addKey(EllipticCurvePublicJwk.getInstance((ECPublicKey) publicKey, keyId));
      }
      return this;
    }

    /**
     * Add a public key, embedded in a KeyPair instance.
     *
     * @param keyPair a key pair instance
     * @param keyId   the key id (optional)
     * @return the current set builder instance
     */
    public SetBuilder withKeyPair(KeyPair keyPair, String keyId) {
      return withPublicKey(keyPair.getPublic(), keyId);

    }

    /**
     * Add a public key, embedded in a X509Certificate instance.
     *
     * @param certificate a certificate instance
     * @param keyId       the key id (optional)
     * @return the current set builder instance
     */
    public SetBuilder withCertificate(X509Certificate certificate, String keyId) {
      return withPublicKey(certificate.getPublicKey(), keyId);
    }

    /**
     * Build and return the JwkSet instance.
     *
     * @return the JWK set instance.
     */
    public JwkSet build() {
      return jwkSet;
    }

  }

}
