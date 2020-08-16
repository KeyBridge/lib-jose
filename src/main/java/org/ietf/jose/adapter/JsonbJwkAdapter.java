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
package org.ietf.jose.adapter;

import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.json.bind.adapter.JsonbAdapter;
import org.ietf.jose.jwk.KeyType;
import org.ietf.jose.jwk.key.*;
import org.ietf.jose.util.JsonbReader;
import org.ietf.jose.util.JsonbWriter;

/**
 * Json Web Key adapter. Provides round-trim serialization of recognized JWK key
 * instances.
 *
 * @author Key Bridge
 * @since v0.10.0 created 2020-08-16
 */
public class JsonbJwkAdapter implements JsonbAdapter<AbstractJwk, String> {

  private static final Logger LOG = Logger.getLogger(JsonbJwkAdapter.class.getName());

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(AbstractJwk obj) throws Exception {
    return new JsonbWriter()
      .withFormatting(true)
      .withAdapters(new JsonbBigIntegerBase64UrlAdapter())
      .withAdapters(new JsonbByteArrayBase64UrlAdapter())
      .marshal(obj);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Evaluate the JSON to determine the key type "kty" field. Use the key type
   * value to route the unmarshal logic.
   */
  @Override
  public AbstractJwk adaptFromJson(String obj) throws Exception {
    if (obj == null || obj.trim().isEmpty()) {
      LOG.warning("JsonbJwkAdapter.adaptFromJson null or empty value");
      return null;
    }
    String json = obj.replaceAll("\\s", "");
    String keyTypePattern = "^.*\"?kty\"?: ?\"?([RSAECoct]{2,3})\"?.*$";
    Pattern p = Pattern.compile(keyTypePattern);
    Matcher m = p.matcher(json);
    if (m.matches()) {
      /**
       * Initialize a new reader.
       */
      JsonbReader reader = new JsonbReader()
        .withAdapters(new JsonbBigIntegerBase64UrlAdapter())
        .withAdapters(new JsonbByteArrayBase64UrlAdapter());
      /**
       * Route logic based on the key type value.
       */
      switch (KeyType.valueOf(m.group(1))) {
        /**
         * EC public and private keys use the same container.
         */
        case EC:
          return reader.unmarshal(json, EllipticCurveJwk.class);

        /**
         * RSA private keys have additional fields. Look for just one.
         */
        case RSA:
          String dPattern = "^.*,\"?d\"?:.*$";
          if (Pattern.compile(dPattern).matcher(json).matches()) {
            return reader.unmarshal(json, RsaPrivateJwk.class);
          } else {
            return reader.unmarshal(json, RsaPublicJwk.class);
          }

        /**
         * Symmetric keys use the same container
         */
        case oct:
          return reader.unmarshal(json, SymmetricJwk.class);

        default:
          throw new AssertionError(m.group(1));
      }
    }
    return null;

  }

}
