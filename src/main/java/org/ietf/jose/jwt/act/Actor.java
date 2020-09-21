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
package org.ietf.jose.jwt.act;

import javax.json.bind.annotation.JsonbProperty;

/**
 * RFC 8693 OAuth 2.0 Token Exchange 4.1. "act" (Actor) Claim
 * <p>
 * The "act" (actor) claim provides a means within a JWT to express that
 * delegation has occurred and identify the acting party to whom authority has
 * been delegated. The "act" claim value is a JSON object, and members in the
 * JSON object are claims that identify the actor. The claims that make up the
 * "act" claim identify and possibly provide additional information about the
 * actor.
 * <p>
 * Claims within the "act" claim pertain only to the identity of the current
 * actor.
 *
 * @author Key Bridge
 * @since v1.3.0 created 2020-09-19
 */
public class Actor {

  /**
   * The identity of the current actor.
   */
  @JsonbProperty("sub")
  private final String subject;
  /**
   * A chain of delegation can be expressed by nesting one "act" claim within
   * another. The outermost "act" claim represents the current actor while
   * nested "act" claims represent prior actors.
   * <p>
   * The least recent actor is the most deeply nested. The nested "act" claims
   * serve as a history trail that connects the initial request and subject
   * through the various delegation steps undertaken before reaching the current
   * actor.
   */
  @JsonbProperty("act")
  private Actor actor;

  /**
   * Construct a new Actor instance with the indicated subject.
   *
   * @param subject the subject identity of the actor
   */
  public Actor(String subject) {
    this.subject = subject;
  }

  /**
   * Get the identity of the current actor.
   *
   * @return the identity of the current actor
   */
  public String getSubject() {
    return subject;
  }

  /**
   * Get the parent actor, if present.
   *
   * @return the parent actor.
   */
  public Actor getActor() {
    return actor;
  }

  /**
   * Wrap the (parent) subject as the actor instance to an earlier claim
   *
   * @param subject the (paretn) actor subject
   */
  public void wrapParent(String subject) {
    this.actor = new Actor(subject);
  }

  /**
   * Set a the actor instance to an earlier claim. This has the effect of
   * wrapping the provided actor with the current.
   * <p>
   * The outermost "act" claim represents the current actor while nested "act"
   * claims represent prior actors. The least recent actor is the most deeply
   * nested.
   *
   * @param actor a parent actor instance
   */
  public void wrapParent(final Actor actor) {
    this.actor = actor;
  }

}
