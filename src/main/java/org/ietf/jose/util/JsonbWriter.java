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
package org.ietf.jose.util;

import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbConfig;
import javax.json.bind.JsonbException;
import javax.json.bind.adapter.JsonbAdapter;
import javax.json.bind.config.BinaryDataStrategy;
import javax.json.bind.serializer.JsonbSerializer;

/**
 * Common JsonB marshaling and un-marshaling utilities. These methods help to
 * serialize and un-serialize object representations to and from JSON.
 *
 * @see <a href="http://json-b.net">JSON Binding</a>
 * @author Key Bridge
 * @since v1.0.0 created 2020-07-15
 * @since v0.10.0 copy 2020-07-14 from lib-jsonb-adapter
 */
public class JsonbWriter {

  /**
   * The configuration setting for the Jsonb parser.
   */
  private JsonbConfig jsonbConfig;
  /**
   * Jsonb provides an abstraction over the JSON Binding framework operations.
   */
  private Jsonb jsonb;

  /**
   * Default no-arg constructor. Sets up the configuration and serializers.
   */
  public JsonbWriter() {
    /**
     * BASE_64 = "BASE_64" Using this strategy, binary data is encoded using the
     * Base64 encoding scheme as specified in RFC 4648 and RFC 2045.
     * <p>
     * I-JSON (”Internet JSON”) is a restricted profile of JSON.
     */
    jsonbConfig = new JsonbConfig()
      .withStrictIJSON(true)
      .withBinaryDataStrategy(BinaryDataStrategy.BASE_64)
      .withPropertyVisibilityStrategy(new JsonbPropertyVisibilityStrategy());
    this.jsonb = JsonbBuilder.create(jsonbConfig);
  }

  /**
   * Construct the writer with a custom configuration.
   *
   * @param jsonbConfig the JsonB configuration
   */
  public JsonbWriter(JsonbConfig jsonbConfig) {
    this.jsonbConfig = jsonbConfig;
    this.jsonb = JsonbBuilder.create(jsonbConfig);
  }

  /**
   * Property used to specify whether or not the serialized JSON data is
   * formatted with linefeeds and indentation. Configures value of FORMATTING
   * property.
   *
   * @param formatting True means serialized data is formatted, false (default)
   *                   means no formatting.
   * @return This JsonbUtility instance.
   */
  public final JsonbWriter withFormatting(final boolean formatting) {
    this.jsonbConfig = jsonbConfig.withFormatting(formatting);
    this.jsonb = JsonbBuilder.create(jsonbConfig);
    return this;
  }

  /**
   * Property used to specify custom serializers. Configures value of
   * {@code SERIALIZERS} property. Calling withSerializers more than once will
   * merge the serializers with previous value.
   *
   * @param serializers Custom serializers which affects serialization.
   * @return This JsonbUtility instance.
   */
  public final JsonbWriter withSerializers(final JsonbSerializer... serializers) {
    this.jsonbConfig = jsonbConfig.withSerializers(serializers);
    this.jsonb = JsonbBuilder.create(jsonbConfig);
    return this;
  }

  /**
   * Property used to specify custom mapping adapters. Configures value of
   * {@code ADAPTERS} property. Calling withAdapters more than once will merge
   * the adapters with previous value.
   *
   * @param adapters Custom mapping adapters which affects serialization and
   *                 deserialization.
   * @return This JsonbConfig instance.
   */
  public final JsonbWriter withAdapters(final JsonbAdapter... adapters) {
    this.jsonbConfig = jsonbConfig.withAdapters(adapters);
    this.jsonb = JsonbBuilder.create(jsonbConfig);
    return this;
  }

  /**
   * Marshal an entity class into a JSON String representation.
   *
   * @param <T>   the entity class type
   * @param clazz the entity class to be written
   * @return the entity class serialized into JSON form
   * @throws JsonbException       If any unexpected problem occurs during the
   *                              serialization, such as I/O error.
   * @throws NullPointerException If any of the parameters are null.
   */
  public final <T> String marshal(T clazz) throws JsonbException, NullPointerException {
    return jsonb.toJson(clazz);
  }

}
