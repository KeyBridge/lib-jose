package org.ietf.jose.jws;

import lombok.EqualsAndHashCode;
import org.ietf.jose.util.JsonMarshaller;

import java.io.IOException;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
@EqualsAndHashCode
public abstract class JsonSerializable {
  /**
   * Serialise to JSON.
   *
   * @return JSON string
   * @throws IOException in case of failure to serialise the object to JSON
   */
  public String toJson() throws IOException {
    return JsonMarshaller.toJson(this);
  }
}
