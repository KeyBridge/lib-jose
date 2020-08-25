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
package org.ietf.jose.jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * JSON Web Token Claims. Provides a complete list of enumerated JWT claim names
 * and their referencing source.
 *
 * @author Key Bridge
 * @since v1.0.1 created 2020-08-25
 */
public enum ClaimType {
  /**
   * Authentication Context Class Reference	[OpenID Connect Core 1.0, Section 2]
   */
  acr,
  /**
   * Authentication Methods References	[OpenID Connect Core 1.0, Section 2]
   */
  amr,
  /**
   * Access Token hash value	[OpenID Connect Core 1.0, Section 2]
   */
  at_hash,
  /**
   * Time when the authentication occurred	[OpenID Connect Core 1.0, Section 2]
   */
  auth_time,
  /**
   * Authorized party - the party to which the ID Token was issued	[OpenID
   * Connect Core 1.0, Section 2]
   */
  azp,
  /**
   * Value used to associate a Client session with an ID Token	[OpenID Connect
   * Core 1.0, Section 2]
   */
  nonce,
  /**
   * Code hash value	[OpenID Connect Core 1.0, Section 3.3.2.11]
   */
  c_hash,
  /**
   * Preferred postal address	[OpenID Connect Core 1.0, Section 5.1]
   */
  address,
  /**
   * Birthday	[OpenID Connect Core 1.0, Section 5.1]
   */
  birthdate,
  /**
   * Preferred e-mail address	[OpenID Connect Core 1.0, Section 5.1]
   */
  email,
  /**
   * True if the e-mail address has been verified; otherwise false	[OpenID
   * Connect Core 1.0, Section 5.1]
   */
  email_verified,
  /**
   * Surname(s) or last name(s)	[OpenID Connect Core 1.0, Section 5.1]
   */
  family_name,
  /**
   * Gender	[OpenID Connect Core 1.0, Section 5.1]
   */
  gender,
  /**
   * Given name(s) or first name(s)	[OpenID Connect Core 1.0, Section 5.1]
   */
  given_name,
  /**
   * Locale	[OpenID Connect Core 1.0, Section 5.1]
   */
  locale,
  /**
   * Middle name(s)	[OpenID Connect Core 1.0, Section 5.1]
   */
  middle_name,
  /**
   * Full name	[OpenID Connect Core 1.0, Section 5.1]
   */
  name,
  /**
   * Casual name	[OpenID Connect Core 1.0, Section 5.1]
   */
  nickname,
  /**
   * Preferred telephone number	[OpenID Connect Core 1.0, Section 5.1]
   */
  phone_number,
  /**
   * True if the phone number has been verified; otherwise false	[OpenID Connect
   * Core 1.0, Section 5.1]
   */
  phone_number_verified,
  /**
   * Profile picture URL	[OpenID Connect Core 1.0, Section 5.1]
   */
  picture,
  /**
   * Shorthand name by which the End-User wishes to be referred to	[OpenID
   * Connect Core 1.0, Section 5.1]
   */
  preferred_username,
  /**
   * Profile page URL	[OpenID Connect Core 1.0, Section 5.1]
   */
  profile,
  /**
   * Time the information was last updated	[OpenID Connect Core 1.0, Section
   * 5.1]
   */
  updated_at,
  /**
   * Web page or blog URL	[OpenID Connect Core 1.0, Section 5.1]
   */
  website,
  /**
   * Time zone	[OpenID Connect Core 1.0, Section 5.1]
   */
  zoneinfo,
  /**
   * Public key used to check the signature of an ID Token	[OpenID Connect Core
   * 1.0, Section 7.4]
   */
  sub_jwk,
  /**
   * Session ID	[OpenID Connect Front-Channel Logout 1.0, Section 3]
   */
  sid,
  /**
   * Issuer	[RFC7519, Section 4.1.1]
   */
  iss,
  /**
   * Subject	[RFC7519, Section 4.1.2]
   */
  sub,
  /**
   * Audience	[RFC7519, Section 4.1.3]
   */
  aud,
  /**
   * Expiration Time	[RFC7519, Section 4.1.4]
   */
  exp,
  /**
   * Not Before	[RFC7519, Section 4.1.5]
   */
  nbf,
  /**
   * Issued At	[RFC7519, Section 4.1.6]
   */
  iat,
  /**
   * JWT ID	[RFC7519, Section 4.1.7]
   */
  jti,
  /**
   * Number of API requests for which the access token can be used	[ETSI GS
   * NFV-SEC 022 V2.7.1]
   */
  at_use_nbr,
  /**
   * Diverted Target of a Call	[RFC-ietf-stir-passport-divert-09]
   */
  div,
  /**
   * Original PASSporT (in Full Form)	[RFC-ietf-stir-passport-divert-09]
   */
  opt,
  /**
   * Confirmation	[RFC7800, Section 3.1]
   */
  cnf,
  /**
   * SIP Call-Id header field value	[RFC8055][RFC3261]
   */
  sip_callid,
  /**
   * SIP CSeq numeric header field parameter value	[RFC8055][RFC3261]
   */
  sip_cseq_num,
  /**
   * SIP Date header field value	[RFC8055][RFC3261]
   */
  sip_date,
  /**
   * SIP From tag header field parameter value	[RFC8055][RFC3261]
   */
  sip_from_tag,
  /**
   * SIP Via branch header field parameter value	[RFC8055][RFC3261]
   */
  sip_via_branch,
  /**
   * Destination Identity String	[RFC8225, Section 5.2.1]
   */
  dest,
  /**
   * Originating Identity String	[RFC8225, Section 5.2.1]
   */
  orig,
  /**
   * Media Key Fingerprint String	[RFC8225, Section 5.2.2]
   */
  mky,
  /**
   * Security Events	[RFC8417, Section 2.2]
   */
  events,
  /**
   * Time of Event	[RFC8417, Section 2.2]
   */
  toe,
  /**
   * Transaction Identifier	[RFC8417, Section 2.2]
   */
  txn,
  /**
   * Resource Priority Header Authorization	[RFC8443, Section 3]
   */
  rph,
  /**
   * Vector of Trust value	[RFC8485]
   */
  vot,
  /**
   * Vector of Trust trustmark URL	[RFC8485]
   */
  vtm,
  /**
   * Attestation level as defined in SHAKEN framework	[RFC8588]
   */
  attest,
  /**
   * Originating Identifier as defined in SHAKEN framework	[RFC8588]
   */
  origid,
  /**
   * jCard data	[RFC8688][RFC7095]
   */
  jcard,
  /**
   * Actor	[RFC8693, Section 4.1]
   */
  act,
  /**
   * Scope Values	[RFC8693, Section 4.2]
   */
  scope,
  /**
   * Client Identifier	[RFC8693, Section 4.3]
   */
  client_id,
  /**
   * Authorized Actor - the party that is authorized to become the actor
   * [RFC8693, Section 4.4]
   */
  may_act;

  /**
   * Get a list of JWT reserved claims identified in RFC7519. This prevents the
   * user from adding a claim for which they should use a setter method. These
   * claims must be configured using the provided getter methods.
   *
   * @return an unmodifiable collection of JWT claim instances.
   */
  public static Collection<ClaimType> getJwtReservedClaims() {
    return Collections.unmodifiableCollection(Arrays.asList(iss, sub, aud, exp, nbf, iat, jti));
  }

  /**
   * Get a list of JWT reserved claims identified in RFC7519. This prevents the
   * user from adding a claim for which they should use a setter method. These
   * claims must be configured using the provided getter methods.
   *
   * @return an unmodifiable collection of JWT claim instances, converted to
   *         Strings.
   */
  public static Collection<String> getJwtReservedClaimNames() {
    return getJwtReservedClaims().stream().map(c -> c.name()).collect(Collectors.toSet());
  }

}
