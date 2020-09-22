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

import java.lang.reflect.Type;
import javax.json.JsonObject;
import javax.json.bind.serializer.DeserializationContext;
import javax.json.bind.serializer.JsonbDeserializer;
import javax.json.stream.JsonParser;
import org.ietf.jose.jwk.KeyType;
import org.ietf.jose.jwk.key.*;
import org.ietf.jose.util.JsonbReader;

/**
 * Json-B deserializer for polymorphic AbstractJwk instances. Provides
 * de-serialization of recognized JWK key instances.
 * <p>
 * This class is referenced by annotation in the `AbstractJwk` class.
 *
 * @see
 * <a href="https://stackoverflow.com/questions/62398858/deserialize-json-into-polymorphic-pojo-with-json-b-yasson">JSON
 * into polymorphic POJO</a>
 * @author Key Bridge
 * @since v0.10.0 created 2020-08-17
 */
public class JsonJwkDeserializer implements JsonbDeserializer<AbstractJwk> {

  /**
   * Initialize a new reader.
   */
  private static final JsonbReader READER = new JsonbReader()
    .withAdapters(new JsonBigIntegerBase64UrlAdapter())
    .withAdapters(new JsonByteArrayBase64UrlAdapter());

  /**
   * {@inheritDoc}
   */
  @Override
  public AbstractJwk deserialize(JsonParser parser, DeserializationContext ctx, Type rtType) {
    return deserializeJwk(parser.getObject());
  }

  /**
   * Internal method to deserialize a JsonObject list entry to an AbstractJwk
   * instance.
   *
   * @param jsonObject a JsonObject instance
   * @return an AbstractJwk instance
   */
  private AbstractJwk deserializeJwk(JsonObject jsonObject) {
    String jsonString = jsonObject.toString();
    AbstractJwk abstractJwk = null;
    switch (KeyType.valueOf(jsonObject.getString("kty"))) {
      /**
       * EC private keys have one additional field.
       */
      case EC:
        abstractJwk = jsonObject.containsKey("d")
                      ? READER.unmarshal(jsonString, EllipticCurvePrivateJwk.class)
                      : READER.unmarshal(jsonString, EllipticCurvePublicJwk.class);
        break;
      /**
       * RSA private keys have additional fields. Look for just one.
       */
      case RSA:
        abstractJwk = jsonObject.containsKey("d")
                      ? READER.unmarshal(jsonString, RsaPrivateJwk.class)
                      : READER.unmarshal(jsonString, RsaPublicJwk.class);
        break;
      /**
       * Symmetric keys use the same container
       */
      case oct:
        abstractJwk = READER.unmarshal(jsonString, SymmetricJwk.class);
        break;

      default:
        throw new AssertionError(jsonObject.getString("kty"));

    }
    return abstractJwk;
  }

}
