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

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.ietf.jose.adapter.XmlAdapterBigIntegerBase64Url;
import org.ietf.jose.jwk.JWK;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.math.BigInteger;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 6.2. Parameters for Elliptic Curve Keys
 * <p>
 * JWKs can represent Elliptic Curve [DSS] keys. In this case, the "kty" member
 * value is "EC".
 * <p>
 * 6.2.1. Parameters for Elliptic Curve Public Keys
 * <p>
 * An Elliptic Curve public key is represented by a pair of coordinates drawn
 * from a finite field, which together define a point on an Elliptic Curve. The
 * following members MUST be present for all Elliptic Curve public keys: "crv",
 * "x"
 * <p>
 * 6.2.2. Parameters for Elliptic Curve Private Keys
 * <p>
 * In addition to the members used to represent Elliptic Curve public keys, the
 * following member MUST be present to represent Elliptic Curve private keys.
 * <p>
 * 6.2.2.1. "d" (ECC Private Key) Parameter
 *
 * @author Key Bridge
 */
@EqualsAndHashCode(callSuper = true)
@Data
@XmlAccessorType(XmlAccessType.FIELD)
public class EllipticCurveJwk extends JWK {

  /**
   * 6.2.1.1. "crv" (Curve) Parameter
   * <p>
   * The "crv" (curve) parameter identifies the cryptographic curve used with
   * the key. Curve values from [DSS] used by this specification are:
   * <p>
   * "P-256", "P-384", "P-521"
   */
  private String crv;
  /**
   * 6.2.1.2. "x" (X Coordinate) Parameter
   * <p>
   * The "x" (x coordinate) parameter contains the x coordinate for the Elliptic
   * Curve point. It is represented as the base64url encoding of the octet
   * string representation of the coordinate, as defined in Section 2.3.5 of
   * SEC1 [SEC1]. The length of this octet string MUST be the full size of a
   * coordinate for the curve specified in the "crv" parameter. For example, if
   * the value of "crv" is "P-521", the octet string must be 66 octets long.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger x;
  /**
   * 6.2.1.3. "y" (Y Coordinate) Parameter
   * <p>
   * The "y" (y coordinate) parameter contains the y coordinate for the Elliptic
   * Curve point. It is represented as the base64url encoding of the octet
   * string representation of the coordinate, as defined in Section 2.3.5 of
   * SEC1 [SEC1]. The length of this octet string MUST be the full size of a
   * coordinate for the curve specified in the "crv" parameter. For example, if
   * the value of "crv" is "P-521", the octet string must be 66 octets long.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger y;
  /**
   * "d" (ECC Private Key) Parameter. MUST be present to represent Elliptic
   * Curve private keys
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger d;
}
