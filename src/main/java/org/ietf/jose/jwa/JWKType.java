/*
 * Copyright 2018 Key Bridge. All rights reserved. Use is subject to license
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
public enum JWKType {
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
