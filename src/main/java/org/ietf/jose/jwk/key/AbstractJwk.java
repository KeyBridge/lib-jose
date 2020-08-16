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

import ch.keybridge.lib.jose.AbstractHeader;
import java.util.List;
import java.util.Objects;
import org.ietf.jose.jwk.KeyOperationType;
import org.ietf.jose.jwk.KeyType;
import org.ietf.jose.jwk.PublicKeyUseType;

/**
 * RFC-7517 JSON Web Key (JWK)
 * <p>
 * 4. JSON Web Key (JWK) Format
 * <p>
 * A JWK is a JSON object that represents a cryptographic key. The members of
 * the object represent properties of the key, including its value. This JSON
 * object MAY contain whitespace and/or line breaks before or after any JSON
 * values or structural characters, in accordance with
 * <a href="https://tools.ietf.org/pdf/rfc7159#section-2">
 * Section 2 of RFC 7159 [RFC7159]</a>. This document defines the key parameters
 * that are not algorithm specific and, thus, common to many keys.
 * <p>
 * 4.1. "kty" (Key Type) Parameter
 * <p>
 * The "kty" (key type) parameter identifies the cryptographic algorithm family
 * used with the key, such as "RSA" or "EC". "kty" values should either be
 * registered in the IANA "JSON Web Key Types" registry established by [JWA] or
 * be a value that contains a Collision- Resistant Name. The "kty" value is a
 * case-sensitive string. This member MUST be present in a JWK.
 * <p>
 * A list of defined "kty" values can be found in the IANA "JSON Web Key Types"
 * registry established by [JWA]; the initial contents of this registry are the
 * values defined in Section 6.1 of [JWA].
 * <p>
 * The key type definitions include specification of the members to be used for
 * those key types. Members used with specific "kty" values can be found in the
 * IANA "JSON Web Key Parameters" registry established by Section 8.1.
 * <p>
 * Developer note: JsonTypeInfo specifies the kty field used by JAXB to
 * determine which sub-class to unmarshal to.
 * <p>
 * Developer note: all sub-classes, which need to be the output of unmarshalling
 * a JWK JSON string, must be listed in JsonSubTypes.
 */
public abstract class AbstractJwk extends AbstractHeader {

  /**
   * 4.1. "kty" (Key Type) Parameter
   * <p>
   * The "kty" (key type) parameter identifies the cryptographic algorithm
   * family used with the key, such as "RSA" or "EC". "kty" values should either
   * be registered in the IANA "JSON Web Key Types" registry established by
   * [JWA] or be a value that contains a Collision- Resistant Name. The "kty"
   * value is a case-sensitive string. This member MUST be present in a JWK.
   * <p>
   * A list of defined "kty" values can be found in the IANA "JSON Web Key
   * Types" registry established by [JWA]; the initial contents of this registry
   * are the values defined in Section 6.1 of [JWA].
   * <p>
   * The key type definitions include specification of the members to be used
   * for those key types. Members used with specific "kty" values can be found
   * in the IANA "JSON Web Key Parameters" registry established by Section 8.1.
   */
  protected KeyType kty;
  /**
   * 4.2. "use" (Public Key Use) Parameter
   * <p>
   * The "use" (public key use) parameter identifies the intended use of the
   * public key. The "use" parameter is employed to indicate whether a public
   * key is used for encrypting data or verifying the signature on data.
   * <p>
   * Values defined by this specification are:
   * <ul>
   * <li> "sig" (signature)</li>
   * <li> "enc" (encryption)</li>
   * </ul>
   * Other values MAY be used. The "use" value is a case-sensitive string. Use
   * of the "use" member is OPTIONAL, unless the application requires its
   * presence.
   * <p>
   * When a key is used to wrap another key and a public key use designation for
   * the first key is desired, the "enc" (encryption) key use value is used,
   * since key wrapping is a kind of encryption. The "enc" value is also to be
   * used for public keys used for key agreement operations.
   * <p>
   * Additional "use" (public key use) values can be registered in the IANA
   * "JSON Web Key Use" registry established by Section 8.2. Registering any
   * extension values used is highly recommended when this specification is used
   * in open environments, in which multiple organizations need to have a common
   * understanding of any extensions used. However, unregistered extension
   * values can be used in closed environments, in which the producing and
   * consuming organization will always be the same.
   */
  protected PublicKeyUseType use;
  /**
   * 4.3. "key_ops" (Key Operations) Parameter
   * <p>
   * The "key_ops" (key operations) parameter identifies the operation(s) for
   * which the key is intended to be used. The "key_ops" parameter is intended
   * for use cases in which public, private, or symmetric keys may be present.
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
   * strings. Duplicate key operation values MUST NOT be present in the array.
   * Use of the "key_ops" member is OPTIONAL, unless the application requires
   * its presence.
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
   * The "use" and "key_ops" JWK members SHOULD NOT be used together; however,
   * if both are used, the information they convey MUST be consistent.
   * Applications should specify which of these members they use, if either is
   * to be used by the application.
   */
  protected List<KeyOperationType> key_ops;

  public AbstractJwk() {
  }

  public KeyType getKty() {
    return kty;
  }

  public void setKty(KeyType kty) {
    this.kty = kty;
  }

  public PublicKeyUseType getUse() {
    return use;
  }

  public void setUse(PublicKeyUseType use) {
    this.use = use;
  }

  public List<KeyOperationType> getKey_ops() {
    return key_ops;
  }

  public void setKey_ops(List<KeyOperationType> key_ops) {
    this.key_ops = key_ops;
  }

  @Override
  public int hashCode() {
    int hash = super.hashCode();
    hash = 79 * hash + Objects.hashCode(this.kty);
    hash = 79 * hash + Objects.hashCode(this.use);
    hash = 79 * hash + Objects.hashCode(this.key_ops);
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
    final AbstractJwk other = (AbstractJwk) obj;
    if (!Objects.equals(this.kty, other.kty)) {
      return false;
    }
    if (this.use != other.use) {
      return false;
    }
    if (!Objects.equals(this.key_ops, other.key_ops)) {
      return false;
    }
    return super.equals(obj);
  }

  @Override
  public String toString() {
    return "AbstractJwk{" + "kty=" + kty + '}';
  }

}
