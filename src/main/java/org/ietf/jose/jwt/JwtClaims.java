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
package org.ietf.jose.jwt;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTransient;
import javax.json.bind.annotation.JsonbTypeAdapter;
import org.ietf.jose.JsonSerializable;
import org.ietf.jose.adapter.JsonZonedDateTimeEpochAdapter;
import org.ietf.jose.util.JsonbReader;
import org.ietf.jose.util.JsonbWriter;

/**
 * RFC 7519 JSON Web Token (JWT)
 * <p>
 * 4. JWT Claims
 * <p>
 * The JWT Claims Set represents a JSON object whose members are the claims
 * conveyed by the JWT. The Claim Names within a JWT Claims Set MUST be unique;
 * JWT parsers MUST either reject JWTs with duplicate Claim Names or use a JSON
 * parser that returns only the lexically last duplicate member name, as
 * specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
 * [ECMAScript].
 * <p>
 * The set of claims that a JWT must contain to be considered valid is context
 * dependent and is outside the scope of this specification. Specific
 * applications of JWTs will require implementations to understand and process
 * some claims in particular ways. However, in the absence of such requirements,
 * all claims that are not understood by implementations MUST be ignored.
 * <p>
 * There are three classes of JWT Claim Names: Registered Claim Names, Public
 * Claim Names, and Private Claim Names.
 * <p>
 * 4.1. Registered Claim Names
 * <p>
 * The following Claim Names are registered in the IANA "JSON Web Token Claims"
 * registry established by Section 10.1. None of the claims defined below are
 * intended to be mandatory to use or implement in all cases, but rather they
 * provide a starting point for a set of useful, interoperable claims.
 * Applications using JWTs should define which specific claims they use and when
 * they are required or optional. All the names are short because a core goal of
 * JWTs is for the representation to be compact.
 *
 * @see <a href="https://www.iana.org/assignments/jwt/jwt.xhtml">JWT Claims</a>
 * @author Key Bridge
 * @since v0.9.2 add fluent setters
 */
public class JwtClaims extends JsonSerializable {

  /**
   * 4.1.1. "iss" (Issuer) Claim The "iss" (issuer) claim identifies the
   * principal that issued the JWT. The processing of this claim is generally
   * application specific. The "iss" value is a case-sensitive string containing
   * a StringOrURI value. Use of this claim is OPTIONAL.
   */
  @JsonbProperty("iss")
  private String issuer;
  /**
   * 4.1.2. "sub" (Subject) Claim The "sub" (subject) claim identifies the
   * principal that is the subject of the JWT. The claims in a JWT are normally
   * statements about the subject. The subject value MUST either be scoped to be
   * locally unique in the context of the issuer or be globally unique. The
   * processing of this claim is generally application specific. The "sub" value
   * is a case-sensitive string containing a StringOrURI value. Use of this
   * claim is OPTIONAL.
   */
  @JsonbProperty("sub")
  private String subject;
  /**
   * 4.1.3. "aud" (Audience) Claim The "aud" (audience) claim identifies the
   * recipients that the JWT is intended for. Each principal intended to process
   * the JWT MUST identify itself with a value in the audience claim. If the
   * principal processing the claim does not identify itself with a value in the
   * "aud" claim when this claim is present, then the JWT MUST be rejected. In
   * the general case, the "aud" value is an array of case- sensitive strings,
   * each containing a StringOrURI value. In the special case when the JWT has
   * one audience, the "aud" value MAY be a single case-sensitive string
   * containing a StringOrURI value. The interpretation of audience values is
   * generally application specific. Use of this claim is OPTIONAL.
   */
  @JsonbProperty("aud")
  private String audience;
  /**
   * 4.1.4. "exp" (Expiration Time) Claim The "exp" (expiration time) claim
   * identifies the expiration time on or after which the JWT MUST NOT be
   * accepted for processing. The processing of the "exp" claim requires that
   * the current date/time MUST be before the expiration date/time listed in the
   * "exp" claim. Implementers MAY provide for some small leeway, usually no
   * more than a few minutes, to account for clock skew. Its value MUST be a
   * number containing a NumericDate value. Use of this claim is OPTIONAL.
   */
  @JsonbProperty("exp")
  @JsonbTypeAdapter(JsonZonedDateTimeEpochAdapter.class)
  private ZonedDateTime expiresAt;
  /**
   * 4.1.5. "nbf" (Not Before) Claim The "nbf" (not before) claim identifies the
   * time before which the JWT MUST NOT be accepted for processing. The
   * processing of the "nbf" claim requires that the current date/time MUST be
   * after or equal to the not-before date/time listed in the "nbf" claim.
   * Implementers MAY provide for some small leeway, usually no more than a few
   * minutes, to account for clock skew. Its value MUST be a number containing a
   * NumericDate value. Use of this claim is OPTIONAL.
   */
  @JsonbProperty("nbf")
  @JsonbTypeAdapter(JsonZonedDateTimeEpochAdapter.class)
  private ZonedDateTime notBefore;
  /**
   * 4.1.6. "iat" (Issued At) Claim The "iat" (issued at) claim identifies the
   * time at which the JWT was issued. This claim can be used to determine the
   * age of the JWT. Its value MUST be a number containing a NumericDate value.
   * Use of this claim is OPTIONAL.
   */
  @JsonbProperty("iat")
  @JsonbTypeAdapter(JsonZonedDateTimeEpochAdapter.class)
  private ZonedDateTime issuedAt;
  /**
   * 4.1.7. "jti" (JWT ID) Claim The "jti" (JWT ID) claim provides a unique
   * identifier for the JWT. The identifier value MUST be assigned in a manner
   * that ensures that there is a negligible probability that the same value
   * will be accidentally assigned to a different data object; if the
   * application uses multiple issuers, collisions MUST be prevented among
   * values produced by different issuers as well. The "jti" claim can be used
   * to prevent the JWT from being replayed. The "jti" value is a case-
   * sensitive string. Use of this claim is OPTIONAL.
   */
  @JsonbProperty("jti")
  private String jwtId;

  /**
   * TODO: Write an adapter to serialize/deserialize claims.
   * <p>
   * A collection of Public and/or Private claims. See RFC 7519 JSON Web Token
   * (JWT) sections 4.2 and 4.3.
   * <p>
   * 4.2. Public Claim Names. Claim Names can be defined at will by those using
   * JWTs. Any new Claim Name should either be registered in the IANA "JSON Web
   * Token Claims" registry.
   * <p>
   * 4.3. Private Claim Names. A producer and consumer of a JWT MAY agree to use
   * Private Claim Names. Private Claim Names are subject to collision and
   * should be used with caution.
   *
   * @see <a href="https://www.iana.org/assignments/jwt/jwt.xhtml">JSON Web
   * Token Claims</a>
   */
  @JsonbTransient
  private Map<String, Object> claims;

  /**
   * Default no-arg constructor. Initialized the `issuedAt` field to the current
   * system time.
   */
  public JwtClaims() {
    this.jwtId = UUID.randomUUID().toString();
    this.issuedAt = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS);
    this.notBefore = issuedAt;
    this.claims = new HashMap<>();
  }

  //<editor-fold defaultstate="collapsed" desc="Getter and Setter">
  /**
   * Get the principal that issued the JWT
   *
   * @return the principal that issued the JWT
   */
  public String getIssuer() {
    return this.issuer;
  }

  /**
   * Identifies the principal that issued the JWT
   *
   * @param issuer the principal that issued the JWT
   * @return the current claims instance
   */
  public JwtClaims withIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  /**
   * Set the principal that issued the JWT
   *
   * @param issuer the principal that issued the JWT
   */
  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  /**
   * The "sub" (subject) claim identifies the principal that is the subject of
   * the JWT.
   *
   * @return the subject of the JWT
   */
  public String getSubject() {
    return this.subject;
  }

  /**
   * Set the principal that is the subject of the JWT.
   *
   * @param subject the subject of the JWT.
   */
  public void setSubject(String subject) {
    this.subject = subject;
  }

  /**
   * Set the principal that is the subject of the JWT.
   *
   * @param subject the subject of the JWT.
   * @return the current claims instance
   */
  public JwtClaims withSubject(String subject) {
    this.subject = subject;
    return this;
  }

  /**
   * The "aud" (audience) claim identifies the recipients that the JWT is
   * intended for.
   *
   * @return the recipients that the JWT is intended for.
   */
  public String getAudience() {
    return this.audience;
  }

  /**
   * The "aud" (audience) claim identifies the recipients that the JWT is
   * intended for.
   *
   * @param audience the recipients that the JWT is intended for.
   */
  public void setAudience(String audience) {
    this.audience = audience;
  }

  /**
   * The "aud" (audience) claim identifies the recipients that the JWT is
   * intended for.
   *
   * @param audience that the JWT is intended for.
   * @return the current claims instance
   */
  public JwtClaims withAudience(String audience) {
    this.audience = audience;
    return this;
  }

  public ZonedDateTime getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(ZonedDateTime expiresAt) {
    this.expiresAt = expiresAt;
  }

  public JwtClaims withExpirationTime(ZonedDateTime expirationTime) {
    /**
     * Developer note: Must truncate the ZonedDateTime to seconds or EQUALS will
     * fail to match due to nanosecond time component.
     */
    this.expiresAt = expirationTime == null ? null : expirationTime.truncatedTo(ChronoUnit.SECONDS);
    return this;
  }

  /**
   * Convenience helper method to set the expiration time.
   *
   * @param duration the JWT duration. Typically this should be 3600 seconds.
   * @return the current claims instance.
   */
  public JwtClaims withDuration(Duration duration) {
    this.expiresAt = issuedAt.plus(duration);
    return this;
  }

  public ZonedDateTime getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(ZonedDateTime notBefore) {
    this.notBefore = notBefore;
  }

  public JwtClaims withNotBefore(ZonedDateTime notBefore) {
    /**
     * Developer note: Must truncate the ZonedDateTime to seconds or EQUALS will
     * fail to match due to nanosecond time component.
     */
    this.notBefore = notBefore == null ? null : notBefore.truncatedTo(ChronoUnit.SECONDS);
    return this;
  }

  /**
   * Identifies the time at which the JWT was issued.
   *
   * @return timestamp when the JWT was issued.
   */
  public ZonedDateTime getIssuedAt() {
    return issuedAt;
  }

  /**
   * Identifies the time at which the JWT was issued.
   * <p>
   * Developer note: `issuedAt` is set to the current system time in the
   * constructor.
   *
   * @param issuedAt timestamp when the JWT was issued.
   */
  public void setIssuedAt(ZonedDateTime issuedAt) {
    this.issuedAt = issuedAt;
  }

  /**
   * Identifies the time at which the JWT was issued.
   * <p>
   * Developer note: `issuedAt` is set to the current system time in the
   * constructor.
   *
   * @param issuedAt timestamp when the JWT was issued.
   * @return the current claims instance
   */
  public JwtClaims withIssuedAt(ZonedDateTime issuedAt) {
    /**
     * Developer note: Must truncate the ZonedDateTime to seconds or EQUALS will
     * fail to match due to nanosecond time component.
     */
    this.issuedAt = issuedAt == null ? null : issuedAt.truncatedTo(ChronoUnit.SECONDS);
    return this;
  }

  /**
   * A unique identifier for the JWT.
   *
   * @return the JWT idenfifier
   */
  public String getJwtId() {
    return this.jwtId;
  }

  /**
   * A unique identifier for the JWT.
   * <p>
   * Developer note: the JWT id is initialized to a random UUID in the
   * constructor. Use this method to replace the default value.
   *
   * @param jwtId the JWT idenfifier
   */
  public void setJwtId(String jwtId) {
    this.jwtId = jwtId;
  }

  /**
   * A unique identifier for the JWT.
   * <p>
   * Developer note: the JWT id is initialized to a random UUID in the
   * constructor. Use this method to replace the default value.
   *
   * @param jwtId a unique identifier for the JWT
   * @return this instance
   */
  public JwtClaims withJwtId(String jwtId) {
    this.jwtId = jwtId;
    return this;
  }

  public Map<String, Object> getClaims() {
    return this.claims;
  }

  public void setClaims(Map<String, Object> claims) {
    this.claims = claims;
  }

  /**
   * Fluent method to add an enumerated claim that does not clash with one of
   * the standard claim names.
   *
   * @param claim      the enumerated claim type
   * @param claimValue the corresponding claim value. For complex claim objects
   *                   the value should be externally transformed to a String
   * @return the current JWT instance
   */
  public JwtClaims withClaim(ClaimType claim, Object claimValue) {
    if (ClaimType.getJwtReservedClaims().contains(claim)) {
      throw new IllegalArgumentException("Cannot use reserved claim name " + claim);
    }
    claims.put(claim.name(), claimValue);
    return this;
  }

  /**
   * Fluent method to add a claim with an arbitrary name that does not clash
   * with one of the standard claim names.
   *
   * @param claim      the claim name
   * @param claimValue the claim value; for complex claim objects the value
   *                   should be externally transformed to a String
   * @return this JwtClaims instance
   */
  public JwtClaims withClaim(String claim, Object claimValue) {
    return addClaim(claim, claimValue);
  }

  /**
   * Fluent method to add a claim with an arbitrary name that does not clash
   * with one of the standard claim names.
   *
   * @param claim      the claim name
   * @param claimValue the claim value; for complex claim objects the value
   *                   should be externally transformed to a String
   * @return this JwtClaims instance
   */
  public JwtClaims addClaim(String claim, Object claimValue) {
    if (ClaimType.getJwtReservedClaimNames().contains(claim)) {
      throw new IllegalArgumentException("Cannot use reserved claim name " + claim);
    }
    claims.put(claim, claimValue);
    return this;
  }//</editor-fold>

  /**
   * Create JWT Claims instance from JSON string
   *
   * @param json a valid JSON string representing JWT claims
   * @return A JwtClaims object
   * @throws IOException on json marshal error
   * @throws Exception   if the date times fail to unmarshal
   */
  public static JwtClaims fromJson(final String json) throws IOException, Exception {
    Class<?> unmarshallingClass = (new HashMap<>()).getClass();
    Map<String, Object> valueMap = (Map<String, Object>) new JsonbReader().unmarshal(json, unmarshallingClass);
    JwtClaims claims = new JwtClaims();
    claims.issuer = (String) valueMap.remove("iss");
    claims.subject = (String) valueMap.remove("sub");
    claims.audience = (String) valueMap.remove("aud");
    claims.jwtId = (String) valueMap.remove("jti");
    claims.expiresAt = unmarshalZonedDateTime(valueMap.remove("exp"));
    claims.notBefore = unmarshalZonedDateTime(valueMap.remove("nbf"));
    claims.issuedAt = unmarshalZonedDateTime(valueMap.remove("iat"));
    claims.claims = valueMap.isEmpty() ? Collections.EMPTY_MAP : valueMap;
    return claims;
  }

  /**
   * Internal helper method to unmarshal an object (expect String, Integer, Long
   * or NULL) to a UTC ZonedDateTime instance.
   *
   * @param v the object instance
   * @return a ZonedDateTime instance, null if the input is null
   */
  private static ZonedDateTime unmarshalZonedDateTime(Object v) {
    return v == null
           ? null
           : ZonedDateTime.ofInstant(Instant.ofEpochSecond(Long.parseLong(String.valueOf(v))), ZoneId.of("UTC"));
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toJson() {
    Map<String, Object> jsonObject = new LinkedHashMap<>();

    if (issuer != null) {
      jsonObject.put("iss", issuer);
    }
    if (subject != null) {
      jsonObject.put("sub", subject);
    }
    if (audience != null) {
      jsonObject.put("aud", audience);
    }
    if (jwtId != null) {
      jsonObject.put("jti", jwtId);
    }
    if (expiresAt != null) {
      jsonObject.put("exp", expiresAt.toEpochSecond());
    }
    if (notBefore != null) {
      jsonObject.put("nbf", notBefore.toEpochSecond());
    }
    if (issuedAt != null) {
      jsonObject.put("iat", issuedAt.toEpochSecond());
    }
    if (claims != null && !claims.isEmpty()) {
      jsonObject.putAll(claims);
    }
    /**
     * Use the generic JsonbWriter since claims can be any object type.
     */
    return new JsonbWriter().withAdapters(new JsonZonedDateTimeEpochAdapter()).marshal(jsonObject);
  }

  @Override
  public int hashCode() {
    int hash = 7;
    hash = 97 * hash + Objects.hashCode(this.issuer);
    hash = 97 * hash + Objects.hashCode(this.subject);
    hash = 97 * hash + Objects.hashCode(this.audience);
    hash = 97 * hash + Objects.hashCode(this.expiresAt);
    hash = 97 * hash + Objects.hashCode(this.notBefore);
    hash = 97 * hash + Objects.hashCode(this.issuedAt);
    hash = 97 * hash + Objects.hashCode(this.jwtId);
    hash = 97 * hash + Objects.hashCode(this.claims);
    return hash;
  }

  /**
   * Compare two timestamps using logical equality (i.e. noon UTC equals 1 pm
   * (+01 hours)). This method is necessary because ZonedDateTime::equals
   * returns false for two (logically) equals times but encoded in different
   * time zones.
   *
   * @param one   one ZonedDateTime instance
   * @param other another ZonedDateTime instance
   * @return true if the times are logically equal
   */
  private boolean isEqual(ZonedDateTime one, ZonedDateTime other) {
    /**
     * Same object or both null
     */
    if (one == other) {
      return true;
    }
    if (one == null) {
      return false;
    }
    /**
     * return the logical time equality.
     */
    return one.truncatedTo(ChronoUnit.SECONDS).isEqual(other.truncatedTo(ChronoUnit.SECONDS));
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    final JwtClaims other = (JwtClaims) obj;
    if (!Objects.equals(this.issuer, other.issuer)) {
      return false;
    }
    if (!Objects.equals(this.subject, other.subject)) {
      return false;
    }
    if (!Objects.equals(this.audience, other.audience)) {
      return false;
    }
    if (!Objects.equals(this.jwtId, other.jwtId)) {
      return false;
    }
    if (!isEqual(this.expiresAt, other.expiresAt)) {
      return false;
    }
    if (!isEqual(this.notBefore, other.notBefore)) {
      return false;
    }
    if (!isEqual(this.issuedAt, other.issuedAt)) {
      return false;
    }
    return Objects.equals(this.claims, other.claims);
  }

}
