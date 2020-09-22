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
package org.ietf.jose.adapter;

import javax.json.bind.adapter.JsonbAdapter;
import org.ietf.jose.jwk.key.EllipticCurveType;

/**
 * Simple converter for the enumerated EllipticCurveType. Replaces the dash '-'
 * character with underscore '_' and vice versa.
 *
 * @author Key Bridge
 * @since v1.3.0 created 2020-09-21
 */
public class EllipticCurveTypeAdapter implements JsonbAdapter<EllipticCurveType, String> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(EllipticCurveType obj) throws Exception {
    return obj.name().replace("_", "-");
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public EllipticCurveType adaptFromJson(String obj) throws Exception {
    return EllipticCurveType.valueOf(obj.replace("-", "_"));
  }

}
