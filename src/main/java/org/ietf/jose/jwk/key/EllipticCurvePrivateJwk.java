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
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * RFC 7518 JSON Web Algorithms (JWA) 6.2.2.1. Parameters for Elliptic Curve
 * Private Keys
 * <p>
 * In addition to the members used to represent Elliptic Curve public keys, the
 * "d" (ECC Private Key) Parameter MUST be present to represent Elliptic Curve
 * private keys.
 *
 * @see <a href="http://www.secg.org/sec1-v2.pdf">Elliptic Curve
 * Cryptography</a>
 * @author Key Bridge
 * @since v1.3.0 created 2020-09-21
 */
public class EllipticCurvePrivateJwk extends EllipticCurvePublicJwk {

  /**
   * 6.2.2.1. "d" (ECC Private Key) Parameter
   * <p>
   * The "d" (ECC private key) parameter contains the Elliptic Curve private key
   * value. It is represented as the base64url encoding of the octet string
   * representation of the private key value, as defined in Section 2.3.7 of
   * SEC1 [SEC1]. The length of this octet string MUST be
   * ceiling(log-base-2(n)/8) octets (where n is the order of the curve).
   */
  private BigInteger d;

  /**
   * Default no-arg constructor. Sets the 'key' value to `EC`.
   */
  public EllipticCurvePrivateJwk() {
    super();
  }

  /**
   * Build a new EC private key instance.
   *
   * @param keyPair a key pair (a public key and a private key).
   * @param keyId   the key id
   * @return a new JWK configuration
   */
  public static EllipticCurvePrivateJwk getInstance(KeyPair keyPair, String keyId) {
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
    EllipticCurvePrivateJwk jwk = new EllipticCurvePrivateJwk();
    jwk.setKid(keyId);
    jwk.setX(publicKey.getW().getAffineX());
    jwk.setY(publicKey.getW().getAffineY());
    jwk.setCrv(EllipticCurveType.fromFieldSize(publicKey.getParams().getCurve().getField().getFieldSize()));
    jwk.setD(privateKey.getS());
    return jwk;
  }

  public BigInteger getD() {
    return this.d;
  }

  public void setD(BigInteger d) {
    this.d = d;
  }

//  public PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
//    try {
////      ECParameterSpec spec = NamedCurve.getECParameterSpec(getCurve());
//      /**
//       * This immutable class specifies the set of domain parameters used with
//       * elliptic curve cryptography (ECC).
//       */
//      EllipticCurve curve = new EllipticCurve(new ECFieldFp(crv.getFieldSize()), x, x);
//      ECParameterSpec parameterSpec = new ECParameterSpec(curve, ECPoint.POINT_INFINITY, x, 0);
//
//      ECPrivateKeySpec privspec = new ECPrivateKeySpec(new BigInteger(Base64url.decode(getD())), spec);
//      ECPrivateKey priv = (ECPrivateKey) ECKeyFactory.INSTANCE.generatePrivate(privspec);
//      return priv;
//    } catch (Exception e) {
//      throw new JsonException("Unable to create private EC key.", e);
//    }
//
//  }
}
