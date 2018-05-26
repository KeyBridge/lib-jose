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

/**
 * RFC 7517 JSON Web Key (JWK)
 * <p>
 * 4.2. "use" (Public Key Use) Parameter
 * <p>
 * The "use" (public key use) parameter identifies the intended use of the
 * public key. The "use" parameter is employed to indicate whether a public key
 * is used for encrypting data or verifying the signature on data.
 * <p>
 * Values defined by this specification are:
 * <ul>
 * <li> "sig" (signature)</li>
 * <li> "enc" (encryption)</li>
 * </ul>
 * <p>
 * Other values MAY be used. The "use" value is a case-sensitive string. Use of
 * the "use" member is OPTIONAL, unless the application requires its presence.
 * <p>
 * When a key is used to wrap another key and a public key use designation for
 * the first key is desired, the "enc" (encryption) key use value is used, since
 * key wrapping is a kind of encryption. The "enc" value is also to be used for
 * public keys used for key agreement operations.
 * <p>
 * Additional "use" (public key use) values can be registered in the IANA "JSON
 * Web Key Use" registry established by Section 8.2. Registering any extension
 * values used is highly recommended when this specification is used in open
 * environments, in which multiple organizations need to have a common
 * understanding of any extensions used. However, unregistered extension values
 * can be used in closed environments, in which the producing and consuming
 * organization will always be the same.
 *
 * @author Key Bridge
 */
public enum PublicKeyUseType {
  /**
   * signature
   */
  sig,
  /**
   * encryption
   */
  enc;
}
