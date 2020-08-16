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
package org.ietf.jose.util;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTransient;
import javax.json.bind.config.PropertyVisibilityStrategy;

/**
 * Define customized property visibility strategy trying to replicate JAXB
 * behavior, which is predictable and uasble good, unlike the mayhem that is
 * Json.
 *
 * @author Key Bridge
 * @since v0.10.0 copy 2020-07-14 from lib-jsonb-adapter
 */
public class JsonbPropertyVisibilityStrategy implements PropertyVisibilityStrategy {

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean isVisible(Field field) {
    for (Annotation annotation : field.getAnnotations()) {
      if (annotation instanceof JsonbTransient) {
        return false;
      }
    }
    /**
     * Do not reveal `static final` attributes.
     */
    return !(Modifier.isStatic(field.getModifiers()) && Modifier.isFinal(field.getModifiers()));
  }

  /**
   * {@inheritDoc} Try to emulate XmlAccessType.FIELD. Ignore all methods unless
   * specifically annotated.
   */
  @Override
  public boolean isVisible(Method method) {
    for (Annotation annotation : method.getAnnotations()) {
      if (annotation instanceof JsonbProperty) {
        return true;
      }
    }
    return false;
  }

}
