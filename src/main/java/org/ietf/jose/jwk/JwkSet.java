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

import java.util.List;
import java.util.Objects;

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
public class JwkSet {

  /**
   * 5.1. "keys" Parameter
   * <p>
   * The value of the "keys" parameter is an array of JWK values. By default,
   * the order of the JWK values within the array does not imply an order of
   * preference among them, although applications of JWK Sets can choose to
   * assign a meaning to the order for their purposes, if desired.
   */
  private List<? extends JsonWebKey> keys;

  public JwkSet() {
  }

  public List<? extends JsonWebKey> getKeys() {
    return this.keys;
  }

  public void setKeys(List<? extends JsonWebKey> keys) {
    this.keys = keys;
  }

  @Override
  public int hashCode() {
    int hash = 3;
    hash = 43 * hash + Objects.hashCode(this.keys);
    return hash;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    final JwkSet other = (JwkSet) obj;
    return Objects.equals(this.keys, other.keys);
  }

  protected boolean canEqual(Object other) {
    return other instanceof JwkSet;
  }

  @Override
  public String toString() {
    return "JwkSet(keys=" + this.getKeys() + ")";
  }
}
