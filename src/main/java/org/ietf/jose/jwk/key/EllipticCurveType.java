/*
 * Copyright 2020 Key Bridge. All rights reserved. Use is subject to license
 * terms.
 *
 * This software code is protected by Copyrights and remains the property of
 * Key Bridge and its suppliers, if any. Key Bridge reserves all rights in and to
 * Copyrights and no license is granted under Copyrights in this Software
 * License Agreement.
 *
 * Key Bridge generally licenses Copyrights for commercialization pursuant to
 * the terms of either a Standard Software Source Code License Agreement or a
 * Standard Product License Agreement. A copy of either Agreement can be
 * obtained upon request by sending an email to info@keybridgewireless.com.
 *
 * All information contained herein is the property of Key Bridge and its
 * suppliers, if any. The intellectual and technical concepts contained herein
 * are proprietary.
 */
package org.ietf.jose.jwk.key;

import java.math.BigInteger;
import javax.json.bind.annotation.JsonbProperty;

/**
 * National Institute of Standards and Technology (NIST) <br>
 * FIPS PUB 186-4 FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION <br>
 * Digital Signature Standard (DSS) <br>
 * FIPS PUB 186-4, July 2013 <br>
 * <p>
 * NIST Recommended Elliptic Curves. The principal parameters for elliptic curve
 * cryptography are the elliptic curve E and a designated point G on E called
 * the base point. The base point has order n, which is a large prime. The
 * number of points on the curve is hn for some integer h (the cofactor), which
 * is not divisible by n. For efficiency reasons, it is desirable to have the
 * cofactor be as small as possible.
 *
 * @see
 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">Digital
 * Signature Standard (DSS)</a>
 * @author Key Bridge
 */
public enum EllipticCurveType {

  /**
   * Curve P-256. The modulus for this curve is
   * {@code p = 2^256 – 2^224 + 2^192 + 2^96 – 1}.
   */
  @JsonbProperty("P-256")
  P_256(256),
  /**
   * Curve P-384. The modulus for this curve is
   * {@code p = 2^384 – 2^128 – 2^96 + 2^32 – 1}
   */
  @JsonbProperty("P-384")
  P_384(384),
  /**
   * Curve P-521. The modulus for this curve is {@code p = 2^521 – 1}
   */
  @JsonbProperty("P-521")
  P_521(521);

  private final int fieldSize;

  private EllipticCurveType(int fieldSize) {
    this.fieldSize = fieldSize;
  }

  /**
   * Get a EC type instance from the EC field size, in bits.
   *
   * @see java.security.spec.ECField
   * @param fieldSize The field size in bits. Must be one of [256, 384, 521]
   * @return the enumerated instance
   */
  public static EllipticCurveType fromFieldSize(int fieldSize) {
    return EllipticCurveType.valueOf("P-" + fieldSize);
  }

  /**
   * Get the EC field size, in bits.
   *
   * @return the EC field size
   */
  public BigInteger getFieldSize() {
    return BigInteger.valueOf(fieldSize);
  }

}
