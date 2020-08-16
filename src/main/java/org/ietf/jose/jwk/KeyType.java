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
package org.ietf.jose.jwk;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
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
 * </pre>
 * <p>
 * The use of "+" in the Implementation Requirements column indicates that the
 * requirement strength is likely to be increased in a future version of the
 * specification.
 *
 * @author Key Bridge
 * @since v0.10.0 created 2020-08-16
 */
public enum KeyType {
  /**
   * Elliptic Curve
   * <p>
   * National Institute of Standards and Technology (NIST), "Digital Signature
   * Standard (DSS)", FIPS PUB 186-4, July 2013
   *
   * @see
   * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">DSS</a>
   */
  EC,
  /**
   * RSA [RFC3447]
   * <p>
   * Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography
   * Specifications Version 2.1
   *
   * @see <a href="https://tools.ietf.org/html/rfc3447">RSA Cryptography</a>
   */
  RSA,
  /**
   * Octet sequence (used to represent symmetric keys)
   */
  oct;

}
