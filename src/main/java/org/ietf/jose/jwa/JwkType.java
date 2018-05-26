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
package org.ietf.jose.jwa;

/**
 * 6. Cryptographic Algorithms for Keys
 * <p>
 * A JSON Web Key (JWK) [JWK] is a JSON data structure that represents a
 * cryptographic key. These keys can be either asymmetric or symmetric. They can
 * hold both public and private information about the key. This section defines
 * the parameters for keys using the algorithms specified by this document.
 * <p>
 * 6.1. "kty" (Key Type) Parameter Values
 * <p>
 * The table below is the set of "kty" (key type) parameter values that are
 * defined by this specification for use in JWKs.
 * <pre>
 * +-------------+--------------------------------+--------------------+
 * | "kty" Param | Key Type                       | Implementation     |
 * | Value       |                                | Requirements       |
 * +-------------+--------------------------------+--------------------+
 * | EC          | Elliptic Curve [DSS]           | Recommended+       |
 * | RSA         | RSA [RFC3447]                  | Required           |
 * | oct         | Octet sequence (used to        | Required           |
 * |             | represent symmetric keys)      |                    |
 * +-------------+--------------------------------+--------------------+
 * </pre> The use of "+" in the Implementation Requirements column indicates
 * that the requirement strength is likely to be increased in a future version
 * of the specification.
 *
 * @author Key Bridge
 */
public enum JwkType {
  /**
   * Elliptic Curve [DSS] (Recommended+)
   * <p>
   * (+) the requirement strength is likely to be increased in a future version
   * of the specification.
   */
  EC,
  /**
   * RSA [RFC3447] (Required)
   */
  RSA,
  /**
   * Octet sequence (used to represent symmetric keys) (Required)
   */
  oct;
}
