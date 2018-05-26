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
 * 4.3. "key_ops" (Key Operations) Parameter
 * <p>
 * The "key_ops" (key operations) parameter identifies the operation(s) for
 * which the key is intended to be used. The "key_ops" parameter is intended for
 * use cases in which public, private, or symmetric keys may be present.
 * <p>
 * Its value is an array of key operation values. Values defined by this
 * specification are:
 * <ul>
 * <li> "sign" (compute digital signature or MAC)
 * <li> "verify" (verify digital signature or MAC)
 * <li> "encrypt" (encrypt content)
 * <li> "decrypt" (decrypt content and validate decryption, if applicable)
 * <li> "wrapKey" (encrypt key)
 * <li> "unwrapKey" (decrypt key and validate decryption, if applicable)
 * <li> "deriveKey" (derive key)
 * <li> "deriveBits" (derive bits not to be used as a key)
 * </ul>
 * <p>
 * (Note that the "key_ops" values intentionally match the "KeyUsage" values
 * defined in the Web Cryptography API [W3C.CR-WebCryptoAPI-20141211]
 * specification.)
 * <p>
 * Other values MAY be used. The key operation values are case- sensitive
 * strings. Duplicate key operation values MUST NOT be present in the array. Use
 * of the "key_ops" member is OPTIONAL, unless the application requires its
 * presence.
 * <p>
 * Multiple unrelated key operations SHOULD NOT be specified for a key because
 * of the potential vulnerabilities associated with using the same key with
 * multiple algorithms. Thus, the combinations "sign" with "verify", "encrypt"
 * with "decrypt", and "wrapKey" with "unwrapKey" are permitted, but other
 * combinations SHOULD NOT be used.
 * <p>
 * Additional "key_ops" (key operations) values can be registered in the IANA
 * "JSON Web Key Operations" registry established by Section 8.3. The same
 * considerations about registering extension values apply to the "key_ops"
 * member as do for the "use" member.
 * <p>
 * The "use" and "key_ops" JWK members SHOULD NOT be used together; however, if
 * both are used, the information they convey MUST be consistent. Applications
 * should specify which of these members they use, if either is to be used by
 * the application.
 *
 * @author Key Bridge
 */
public enum KeyOperationType {
  /**
   * compute digital signature or MAC
   */
  sign,
  /**
   * verify digital signature or MAC
   */
  verify,
  /**
   * encrypt content
   */
  encrypt,
  /**
   * decrypt content and validate decryption, if applicable
   */
  decrypt,
  /**
   * encrypt key
   */
  wrapKey,
  /**
   * decrypt key and validate decryption, if applicable
   */
  unwrapKey,
  /**
   * derive key
   */
  deriveKey,
  /**
   * derive bits not to be used as a key
   */
  deriveBits;

}
