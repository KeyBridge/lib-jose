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

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import javax.json.bind.annotation.JsonbTypeAdapter;
import org.ietf.jose.adapter.EllipticCurveTypeAdapter;
import org.ietf.jose.jwk.KeyType;

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
 * "crv" and "x" members MUST be present for all Elliptic Curve public.
 * <p>
 * The "y" member MUST also be present for Elliptic Curve public keys for the
 * "P-256", "P-384", and "P-521" curves.
 *
 * @author Key Bridge
 * @since v1.3.0 created 2020-09-21
 */
public class EllipticCurvePublicJwk extends AbstractJwk {

  /**
   * 6.2.1.1. "crv" (Curve) Parameter
   * <p>
   * The "crv" (curve) parameter identifies the cryptographic curve used with
   * the key. Curve values from [DSS] used by this specification are: "P-256",
   * "P-384", "P-521".
   */
  @JsonbTypeAdapter(EllipticCurveTypeAdapter.class)
  protected EllipticCurveType crv;
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
  protected BigInteger x;
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
  protected BigInteger y;

  /**
   * Default no-arg constructor. Sets the 'key' value to `EC`.
   */
  public EllipticCurvePublicJwk() {
    super(KeyType.EC);
  }

  /**
   * Construct a new EC public key instance.
   *
   * @param publicKey the EC public key instance
   * @param keyId     the key id
   * @return a new JWK
   */
  public static EllipticCurvePublicJwk getInstance(ECPublicKey publicKey, String keyId) {
    EllipticCurvePublicJwk jwk = new EllipticCurvePrivateJwk();
    jwk.setX(publicKey.getW().getAffineX());
    jwk.setY(publicKey.getW().getAffineY());
    jwk.setCrv(EllipticCurveType.fromFieldSize(publicKey.getParams().getCurve().getField().getFieldSize()));
    jwk.setKid(keyId);
    return jwk;
  }

  public EllipticCurveType getCrv() {
    return this.crv;
  }

  public void setCrv(EllipticCurveType crv) {
    this.crv = crv;
  }

  public BigInteger getX() {
    return this.x;
  }

  public void setX(BigInteger x) {
    this.x = x;
  }

  public BigInteger getY() {
    return this.y;
  }

  public void setY(BigInteger y) {
    this.y = y;
  }

}
