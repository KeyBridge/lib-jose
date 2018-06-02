package org.ietf.jose.jws;

import org.ietf.jose.util.JsonMarshaller;

import java.io.IOException;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
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

  public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof JsonSerializable)) return false;
    final JsonSerializable other = (JsonSerializable) o;
    if (!other.canEqual((Object) this)) return false;
    return true;
  }

  public int hashCode() {
    int result = 1;
    return result;
  }

  protected boolean canEqual(Object other) {
    return other instanceof JsonSerializable;
  }
}
