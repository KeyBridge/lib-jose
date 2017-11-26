package ch.keybridge.jose.io;

import org.eclipse.persistence.jaxb.MarshallerProperties;
import org.eclipse.persistence.jaxb.UnmarshallerProperties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.io.StringWriter;

/**
 * Utility class that (un)marshals from/to JSON
 */
public class JsonUtility<T> {
  private final Class<T> clazz;
  private final Marshaller marshaller;
  private final Unmarshaller unmarshaller;

  /**
   * Create a JSON (un) marshaller.
   *
   * No pretty formatting of output JSON.
   * @param clazz class to build an (un)marshaller for
   * @throws JAXBException if unable to create a JAXBContext for the desired class
   */
  public JsonUtility(Class<T> clazz) throws JAXBException {
    this.clazz = clazz;
    JAXBContext context = JAXBContext.newInstance(clazz);
    marshaller = context.createMarshaller();
    marshaller.setProperty(MarshallerProperties.MEDIA_TYPE, "application/json");
    marshaller.setProperty(MarshallerProperties.JSON_INCLUDE_ROOT, false);
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
    unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
    unmarshaller.setProperty(UnmarshallerProperties.MEDIA_TYPE, "application/json");
    unmarshaller.setProperty(UnmarshallerProperties.JSON_INCLUDE_ROOT, false);
  }

  /**
   * Create a JSON (un) marshaller.
   * @param clazz class to build an (un)marshaller for
   * @param prettyFormat if set to true, will output nicely formatted JSON strings
   * @throws JAXBException if unable to create a JAXBContext for the desired class
   */
  public JsonUtility(Class<T> clazz, boolean prettyFormat) throws JAXBException {
    this.clazz = clazz;
    JAXBContext context = JAXBContext.newInstance(clazz);
    marshaller = context.createMarshaller();
    marshaller.setProperty(MarshallerProperties.MEDIA_TYPE, "application/json");
    marshaller.setProperty(MarshallerProperties.JSON_INCLUDE_ROOT, false);
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, prettyFormat);
    unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
    unmarshaller.setProperty(UnmarshallerProperties.MEDIA_TYPE, "application/json");
    unmarshaller.setProperty(UnmarshallerProperties.JSON_INCLUDE_ROOT, false);
  }

  /**
   * Marshal to a JSON string
   * @param value object to me marshaled
   * @return non-null string
   */
  public String toJson(T value) throws JAXBException {
    StringWriter writer = new StringWriter();
    marshaller.marshal(value, writer);
    return writer.toString();
  }

  /**
   * Unmarshal an object from JSON
   * @param json json string representing the object
   * @return a non-null object instance
   */
  public T fromJson(String json) throws JAXBException {
    return unmarshaller.unmarshal(new StreamSource(new StringReader(json)), clazz).getValue();
  }
}
