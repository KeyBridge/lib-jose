package ch.keybridge.jose.jwk;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * 5. JWK Set Format
 * <p>
 * A JWK Set is a JSON object that represents a set of JWKs. The JSON object
 * MUST have a "keys" member, with its value being an array of JWKs. This JSON
 * object MAY contain whitespace and/or line breaks. The member names within a
 * JWK Set MUST be unique; JWK Set parsers MUST either reject JWK Sets with
 * duplicate member names or use a JSON parser that returns only the lexically
 * last duplicate member name, as specified in Section 15.12 ("The JSON Object")
 * of ECMAScript 5.1 [ECMAScript].
 * <p>
 * Additional members can be present in the JWK Set; if not understood by
 * implementations encountering them, they MUST be ignored. Parameters for
 * representing additional properties of JWK Sets should either be registered in
 * the IANA "JSON Web Key Set Parameters" registry established by Section 8.4 or
 * be a value that contains a Collision-Resistant Name.
 * <p>
 * Implementations SHOULD ignore JWKs within a JWK Set that use "kty" (key type)
 * values that are not understood by them, that are missing required members, or
 * for which values are out of the supported ranges.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwkSet {

  /**
   * 5.1. "keys" Parameter
   * <p>
   * The value of the "keys" parameter is an array of JWK values. By default,
   * the order of the JWK values within the array does not imply an order of
   * preference among them, although applications of JWK Sets can choose to
   * assign a meaning to the order for their purposes, if desired.
   */
  @XmlElement(required = true)
  List<? extends JsonWebKey> keys;

  @Override
  public String toString() {
    return "JWKSet{"
      + "keys=" + keys
      + '}';
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    JwkSet jwkSet = (JwkSet) o;

    return keys != null ? keys.equals(jwkSet.keys) : jwkSet.keys == null;
  }

  @Override
  public int hashCode() {
    return keys != null ? keys.hashCode() : 0;
  }
}
