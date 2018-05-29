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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.ietf.jose.adapter.XmlAdapterBigIntegerBase64Url;
import org.ietf.jose.jwk.JWK;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 6.3.1. Parameters for RSA Public Keys
 * <p>
 * The following members MUST be present for RSA public keys.
 */
@EqualsAndHashCode(callSuper = true)
@ToString
@Getter
@Setter
@XmlAccessorType(XmlAccessType.FIELD)
public class RsaPublicJwk extends JWK {

  /**
   * 6.3.1.1. "n" (Modulus) Parameter
   * <p>
   * The "n" (modulus) parameter contains the modulus value for the RSA public
   * key. It is represented as a Base64urlUInt-encoded value.
   * <p>
   * Note that implementers have found that some cryptographic libraries prefix
   * an extra zero-valued octet to the modulus representations they return, for
   * instance, returning 257 octets for a 2048-bit key, rather than 256.
   * Implementations using such libraries will need to take care to omit the
   * extra octet from the base64url-encoded representation.
   */
  @XmlElement(name = "n")
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  protected BigInteger modulus;

  /**
   * 6.3.1.2. "e" (Exponent) Parameter
   * <p>
   * The "e" (exponent) parameter contains the exponent value for the RSA public
   * key. It is represented as a Base64urlUInt-encoded value.
   * <p>
   * For instance, when representing the value 65537, the octet sequence to be
   * base64url-encoded MUST consist of the three octets [1, 0, 1]; the resulting
   * representation for this value is "AQAB".
   */
  @XmlElement(name = "e")
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  protected BigInteger publicExponent;

  public static RsaPublicJwk getInstance(RSAPublicKey publicKey) {
    RsaPublicJwk jwkRsaKey = new RsaPrivateJwk();
    jwkRsaKey.setPublicExponent(publicKey.getPublicExponent());
    jwkRsaKey.setModulus(publicKey.getModulus());
    return jwkRsaKey;
  }

  public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec spec = new RSAPublicKeySpec(getModulus(), getPublicExponent());
    return kf.generatePublic(spec);
  }
}
