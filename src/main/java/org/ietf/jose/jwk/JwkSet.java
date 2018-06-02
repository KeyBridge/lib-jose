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
package org.ietf.jose.jwk;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.util.List;

/**
 * RFC 7517 JSON Web Key (JWK)
 * <p>
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
  private List<? extends JsonWebKey> keys;

  public JwkSet() {
  }

  public List<? extends JsonWebKey> getKeys() {
    return this.keys;
  }

  public void setKeys(List<? extends JsonWebKey> keys) {
    this.keys = keys;
  }

  public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof JwkSet)) return false;
    final JwkSet other = (JwkSet) o;
    if (!other.canEqual((Object) this)) return false;
    final Object this$keys = this.getKeys();
    final Object other$keys = other.getKeys();
    if (this$keys == null ? other$keys != null : !this$keys.equals(other$keys)) return false;
    return true;
  }

  public int hashCode() {
    final int PRIME = 59;
    int result = 1;
    final Object $keys = this.getKeys();
    result = result * PRIME + ($keys == null ? 43 : $keys.hashCode());
    return result;
  }

  protected boolean canEqual(Object other) {
    return other instanceof JwkSet;
  }

  public String toString() {
    return "JwkSet(keys=" + this.getKeys() + ")";
  }
}
