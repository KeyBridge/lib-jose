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
import javax.json.bind.serializer.JsonbDeserializer;

/**
 * Common JsonB marshaling and un-marshaling utilities. These methods help to
 * serialize and un-serialize object representations to and from JSON.
 *
 * @see <a href="http://json-b.net">JSON Binding</a>
 * @author Key Bridge
 * @since v1.0.0 created 2020-07-15
 * @since v0.10.0 copy 2020-07-14 from lib-jsonb-adapter
 */
public class JsonbReader {

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
  public JsonbReader() {
    /**
     * BASE_64 = "BASE_64" Using this strategy, binary data is encoded using the
     * Base64 encoding scheme as specified in RFC 4648 and RFC 2045.
     * <p>
     * I-JSON (”Internet JSON”) is a restricted profile of JSON.
     */
    jsonbConfig = new JsonbConfig()
      .withBinaryDataStrategy(BinaryDataStrategy.BASE_64)
      .withPropertyVisibilityStrategy(new JsonbPropertyVisibilityStrategy());
    this.jsonb = JsonbBuilder.create(jsonbConfig);
  }

  /**
   * Construct the reader with a custom configuration.
   *
   * @param jsonbConfig the custom configuratino
   */
  public JsonbReader(JsonbConfig jsonbConfig) {
    this.jsonbConfig = jsonbConfig;
    this.jsonb = JsonbBuilder.create(jsonbConfig);
  }

  /**
   * Property used to specify custom deserializers. Configures value of
   * {@code DESERIALIZERS} property. Calling withDeserializers more than once
   * will merge the deserializers with previous value.
   *
   * @param deserializers Custom deserializers which affects deserialization.
   * @return This JsonbUtility instance.
   */
  public final JsonbReader withDeserializers(final JsonbDeserializer... deserializers) {
    this.jsonbConfig = jsonbConfig.withDeserializers(deserializers);
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
  public final JsonbReader withAdapters(final JsonbAdapter... adapters) {
    this.jsonbConfig = jsonbConfig.withAdapters(adapters);
    this.jsonb = JsonbBuilder.create(jsonbConfig);
    return this;
  }

  /**
   * Parse a JSON file into a container class. This method calls the JsonB
   * un-marshaller and returns a class containing all of the content defined in
   * the XML file. Reads in a JSON data from the specified string and return the
   * resulting content tree.
   *
   * @param <T>   the class type that is returned
   * @param json  the JSON source content
   * @param clazz the class type that is parsed - this is the same as the class
   *              type that is returned
   * @return the JSON source parsed into the identified class type
   * @throws JsonbException       If any unexpected error(s) occur(s) during
   *                              deserialization.
   * @throws NullPointerException If any of the parameters are null.
   */
  public final <T> T unmarshal(String json, Class<T> clazz) throws JsonbException, NullPointerException {
    return jsonb.fromJson(json, clazz);
  }
}
