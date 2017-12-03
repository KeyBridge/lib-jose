package ch.keybridge.jose.util;

import org.eclipse.persistence.jaxb.MarshallerProperties;
import org.eclipse.persistence.jaxb.UnmarshallerProperties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 02/12/2017
 */
public class JsonMarshaller {
  private final static String MEDIA_TYPE = "application/json";
  private static final Logger LOG = Logger.getLogger(JsonMarshaller.class.getCanonicalName());
  private static Map<Class<?>, Marshaller> marshallers = new ConcurrentHashMap<>();
  private static Map<Class, Unmarshaller> unmarshallers = new ConcurrentHashMap<>();

  /**
   * Marshal to a JSON string
   *
   * @param value object to me marshaled
   * @param clazz class of source object
   * @return non-null string
   */
  public static String toJson(Object value, Class<?> clazz) throws JAXBException {
    StringWriter writer = new StringWriter();
    Marshaller marshaller = marshallers.computeIfAbsent(clazz, JsonMarshaller::createMarshaller);
    if (marshaller == null) throw new JAXBException("Unable to create marshaller!");
    marshaller.marshal(value, writer);
    return writer.toString();
  }

  /**
   * Unmarshal an object from JSON
   *
   * @param json  json string representing the object
   * @param clazz class of target object
   * @return a non-null object instance
   */
  public static <T> T fromJson(String json, Class<T> clazz) throws JAXBException {
    Unmarshaller unmarshaller = unmarshallers.computeIfAbsent(clazz, JsonMarshaller::createUnmarshaller);
    if (unmarshaller == null) throw new JAXBException("Unable to create unmarshaller!");
    return unmarshaller.unmarshal(new StreamSource(new StringReader(json)), clazz).getValue();
  }

  /**
   * Create a marshaller for a JAXB-annotated class
   *
   * @param clazz class
   * @return marshaller or null in case of failure to create a marshaller
   */
  private static Marshaller createMarshaller(Class clazz) {
    try {
      Marshaller marshaller = JAXBContext.newInstance(clazz).createMarshaller();
      marshaller.setProperty(MarshallerProperties.MEDIA_TYPE, MEDIA_TYPE);
      marshaller.setProperty(MarshallerProperties.JSON_INCLUDE_ROOT, true);
      return marshaller;
    } catch (JAXBException e) {
      LOG.log(Level.SEVERE, "Unable to create marshaller for class " + clazz.getCanonicalName(), e);
      return null;
    }
  }

  /**
   * Create an unmarshaller for a JAXB-annotated class
   *
   * @param clazz class
   * @return unmarshaller or null in case of failure to create a marshaller
   */
  private static Unmarshaller createUnmarshaller(Class clazz) {
    try {
      Unmarshaller unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
      unmarshaller.setProperty(UnmarshallerProperties.MEDIA_TYPE, MEDIA_TYPE);
      unmarshaller.setProperty(UnmarshallerProperties.JSON_INCLUDE_ROOT, false);
      return unmarshaller;
    } catch (JAXBException e) {
      LOG.log(Level.SEVERE, "Unable to create unmarshaller for class " + clazz.getCanonicalName(), e);
      return null;
    }
  }
}
