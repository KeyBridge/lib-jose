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
package org.ietf.jose.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import java.io.IOException;

/**
 * A JSON serialization utility. Uses the Jackson JSON serializer with a
 * reasonable default configuration. See the "static" code block for details.
 */
public class JsonMarshaller {

  /**
   * ObjectMapper provides functionality for reading and writing JSON, either to
   * and from basic POJOs (Plain Old Java Objects), or to and from a
   * general-purpose JSON Tree Model (JsonNode)
   */
  private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  /**
   * Builder object that can be used for per-serialization configuration of
   * serialization parameters, such as JSON View and root type to use.
   */
  private final static ObjectWriter OBJECT_WRITER;

  static {
    /**
     * Set the serializer to not output empty fields. That is, instead of having
     * <pre>{"field1":10,"field2":null}</pre> we will have
     * <pre>{"field1":10}</pre>
     */
    OBJECT_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    /**
     * Enable the Jackson annotation introspector. The only instance where
     * Jackson annotations are used, is in the JsonWebKey class, in order to
     * distinguish between concrete JsonWebKey types.
     *
     * @see org.ietf.jose.jwk.JsonWebKey
     */
    OBJECT_MAPPER.setAnnotationIntrospector(new JacksonAnnotationIntrospector());
    /**
     * Enable JAXB annotation processing. JAXB annotations are used on all
     * entity classes in this library.
     */
    OBJECT_MAPPER.registerModule(new JaxbAnnotationModule());
    OBJECT_WRITER = OBJECT_MAPPER.writerWithDefaultPrettyPrinter();
  }

  /**
   * Serialize object to JSON.
   *
   * @param value object to serialize
   * @return A JSON string representing the object
   * @throws IOException Error encountered while serializing
   */
  public static String toJson(Object value) throws IOException {
    return OBJECT_MAPPER.writeValueAsString(value);
  }

  /**
   * Serialize object to pretty-formatted JSON.
   *
   * @param value object to serialize
   * @return A JSON string representing the object
   * @throws IOException Error encountered while serializing
   */
  public static String toJsonPrettyFormatted(Object value) throws IOException {
    return OBJECT_WRITER.writeValueAsString(value);
  }

  /**
   * Deserialize an object from JSON
   *
   * @param <T>   the class type
   * @param json  json string representing the object
   * @param clazz class of target object
   * @return a non-null object instance
   * @throws java.io.IOException if a low-level I/O problem such as unexpected
   *                             end-of-input) occurs
   */
  public static <T> T fromJson(String json, Class<T> clazz) throws IOException {
    return OBJECT_MAPPER.readValue(json, clazz);
  }
}
