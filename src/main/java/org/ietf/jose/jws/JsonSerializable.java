package org.ietf.jose.jws;

import org.ietf.jose.util.JsonbUtility;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public abstract class JsonSerializable {

  /**
   * Serialize this instance to a JSON string.
   *
   * @return this class instance as a JSON encoded string.
   */
  public String toJson() {
    return new JsonbUtility().marshal(this);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Safely serialize this instance to a JSON string. Returns an error message
   * on serialization error.
   */
  @Override
  public String toString() {
    return toJson();
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
