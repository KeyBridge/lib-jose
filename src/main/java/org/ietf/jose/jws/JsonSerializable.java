package org.ietf.jose.jws;

import java.io.IOException;
import org.ietf.jose.util.JsonMarshaller;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public abstract class JsonSerializable {

  /**
   * Serialize this instance to a JSON string.
   *
   * @return this class instance as a JSON encoded string.
   * @throws java.io.IOException on serialization error
   */
  public String toJson() throws IOException {
    return JsonMarshaller.toJson(this);
  }

  /**
   * Safely serialize this instance to a JSON string. Returns an error message
   * on serialization error.
   * <p>
   * {@inheritDoc}
   */
  @Override
  public String toString() {
    try {
      return JsonMarshaller.toJson(this);
    } catch (IOException ex) {
      return this.getClass().getSimpleName() + " serializer error " + ex.getMessage();
    }
  }

  /**
   * Inspect the other class to determine if this and the other class are the
   * same instance type.
   *
   * @param other the other class
   * @return TRUE if {@code this} is an instance of {@code other}
   */
  protected boolean canEqual(Object other) {
    return this.getClass().isInstance(other);
  }
}
