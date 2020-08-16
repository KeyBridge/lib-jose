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

import javax.json.bind.JsonbConfig;
import javax.json.bind.JsonbException;
import javax.json.bind.adapter.JsonbAdapter;
import javax.json.bind.config.BinaryDataStrategy;
import javax.json.bind.serializer.JsonbDeserializer;
import javax.json.bind.serializer.JsonbSerializer;
import org.ietf.jose.adapter.*;

/**
 * Common JsonB marshaling and un-marshaling utilities. These methods help to
 * serialize and un-serialize object representations to and from JSON.
 *
 * @see <a href="http://json-b.net">JSON Binding</a>
 * @author Key Bridge
 * @since v1.0.0 created 2020-07-15
 * @since v0.10.0 copy 2020-07-14 from lib-jsonb-adapter
 */
public class JsonbUtility {

  /**
   * The JsonB reader instance.
   */
  private JsonbReader reader;
  /**
   * The JsonB writer instance.
   */
  private JsonbWriter writer;

  /**
   * Default no-arg constructor. Sets up the reader and writer with a complete
   * configuration. Note that extension adapters can be added separately.
   */
  public JsonbUtility() {
    /**
     * Configure and create the reader and writer instance using the same base
     * configuration.
     */
    JsonbConfig jsonbConfig = new JsonbConfig()
      .withStrictIJSON(true)
      .withBinaryDataStrategy(BinaryDataStrategy.BASE_64_URL)
      .withPropertyVisibilityStrategy(new JsonbPropertyVisibilityStrategy())
      .withAdapters(new JsonbBigIntegerBase64UrlAdapter())
      .withAdapters(new JsonbByteArrayBase64UrlAdapter())
      .withAdapters(new JsonbJweHeaderAdapter())
      .withAdapters(new JsonbJwsHeaderAdapter())
      .withAdapters(new JsonbX509CertificateAdapter())
      .withAdapters(new JsonbZonedDateTimeEpochAdapter());
    reader = new JsonbReader(jsonbConfig);
    writer = new JsonbWriter(jsonbConfig);
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
  public final JsonbUtility withAdapters(final JsonbAdapter... adapters) {
    reader = reader.withAdapters(adapters);
    writer = writer.withAdapters(adapters);
    return this;
  }

  /**
   * Property used to specify custom deserializers. Configures value of
   * {@code DESERIALIZERS} property. Calling withDeserializers more than once
   * will merge the deserializers with previous value.
   *
   * @param deserializers Custom deserializers which affects deserialization.
   * @return This JsonbUtility instance.
   */
  public final JsonbUtility withDeserializers(final JsonbDeserializer... deserializers) {
    reader = reader.withDeserializers(deserializers);
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
  public final JsonbUtility withSerializers(final JsonbSerializer... serializers) {
    writer = writer.withSerializers(serializers);
    return this;
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
  public final JsonbUtility withFormatting(final boolean formatting) {
    writer = writer.withFormatting(formatting);
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
    return writer.marshal(clazz);
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
    return reader.unmarshal(json, clazz);
  }

}
