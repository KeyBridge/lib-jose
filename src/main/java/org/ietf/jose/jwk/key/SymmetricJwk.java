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
package org.ietf.jose.jwk.key;

import org.ietf.jose.jwk.KeyType;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 6.4. Parameters for Symmetric Keys
 * <p>
 * When the JWK "kty" member value is "oct" (octet sequence), the member "k"
 * (see Section 6.4.1) is used to represent a symmetric key (or another key
 * whose value is a single octet sequence). An "alg" member SHOULD also be
 * present to identify the algorithm intended to be used with the key, unless
 * the application uses another means or convention to determine the algorithm
 * used.
 */
public class SymmetricJwk extends AbstractJwk {

  /**
   * 6.4.1. "k" (Key Value) Parameter
   * <p>
   * The "k" (key value) parameter contains the value of the symmetric (or other
   * single-valued) key. It is represented as the base64url encoding of the
   * octet sequence containing the key value.
   */
  private byte[] k;

  /**
   * Default no-arg constructor. Sets the 'key' value to `oct` for "Octet
   * sequence" (used to represent symmetric keys)
   */
  public SymmetricJwk() {
    super(KeyType.oct);
  }

  public byte[] getK() {
    return this.k;
  }

  public void setK(byte[] k) {
    this.k = k;
  }

}
