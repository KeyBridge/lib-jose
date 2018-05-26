package org.ietf.jose.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import java.io.IOException;

/**
 * A JSON serialization utility. Uses Jackson JSON serializer with reasonable
 * configuration, see the "static" code block for details.
 */
public class JsonMarshaller {

  private final static ObjectMapper mapper = new ObjectMapper();

  static {
    /**
     * Set the serializer to not output empty fields. That is, instead of having
     * <pre>{"field1":10,"field2":null}</pre> we will have
     * <pre>{"field1":10}</pre>
     */
    mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    /**
     * Enable the Jackson annotation introspector. The only instance where
     * Jackson annotations are used, is in the JsonWebKey class, in order to
     * distinguish between concrete JsonWebKey types.
     *
     * @see org.ietf.jose.jwk.JsonWebKey
     */
    mapper.setAnnotationIntrospector(new JacksonAnnotationIntrospector());
    /**
     * Enable JAXB annotation processing. JAXB annotations are used on all
     * entity classes in this library.
     */
    mapper.registerModule(new JaxbAnnotationModule());
  }

  /**
   * Serialize object to JSON.
   *
   * @param value object to serialize
   * @return A JSON string representing the object
   * @throws IOException Error encountered while serializing
   */
  public static String toJson(Object value) throws IOException {
    return mapper.writeValueAsString(value);
  }

  /**
   * Deserialize an object from JSON
   *
   * @param json  json string representing the object
   * @param clazz class of target object
   * @return a non-null object instance
   */
  public static <T> T fromJson(String json, Class<T> clazz) throws IOException {
    return mapper.readValue(json, clazz);
  }
}
