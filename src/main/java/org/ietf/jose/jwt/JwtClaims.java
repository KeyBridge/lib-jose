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
import java.time.Instant;
import java.time.temporal.ChronoField;
import java.util.*;
import java.util.stream.Collectors;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.ietf.jose.adapter.XmlAdapterInstantLong;
import org.ietf.jose.jws.JsonSerializable;
import org.ietf.jose.util.JsonMarshaller;

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
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwtClaims extends JsonSerializable {

  /**
   * 4.1.1. "iss" (Issuer) Claim The "iss" (issuer) claim identifies the
   * principal that issued the JWT. The processing of this claim is generally
   * application specific. The "iss" value is a case-sensitive string containing
   * a StringOrURI value. Use of this claim is OPTIONAL.
   */
  @XmlElement(name = "iss")
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
  @XmlElement(name = "sub")
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
  @XmlElement(name = "aud")
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
  @XmlElement(name = "exp")
  @XmlJavaTypeAdapter(type = Instant.class, value = XmlAdapterInstantLong.class)
  private Instant expirationTime;
  /**
   * 4.1.5. "nbf" (Not Before) Claim The "nbf" (not before) claim identifies the
   * time before which the JWT MUST NOT be accepted for processing. The
   * processing of the "nbf" claim requires that the current date/time MUST be
   * after or equal to the not-before date/time listed in the "nbf" claim.
   * Implementers MAY provide for some small leeway, usually no more than a few
   * minutes, to account for clock skew. Its value MUST be a number containing a
   * NumericDate value. Use of this claim is OPTIONAL.
   */
  @XmlElement(name = "nbf")
  @XmlJavaTypeAdapter(type = Instant.class, value = XmlAdapterInstantLong.class)
  private Instant notBefore;
  /**
   * 4.1.6. "iat" (Issued At) Claim The "iat" (issued at) claim identifies the
   * time at which the JWT was issued. This claim can be used to determine the
   * age of the JWT. Its value MUST be a number containing a NumericDate value.
   * Use of this claim is OPTIONAL.
   */
  @XmlElement(name = "iat")
  @XmlJavaTypeAdapter(type = Instant.class, value = XmlAdapterInstantLong.class)
  private Instant issuedAt;
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
  @XmlElement(name = "jti")
  private String jwtId;

  public JwtClaims() {
  }

  /**
   * Strip the sub-second component of a java.time.Instant to ensure conformance
   * with the JWT NumericDate timestamp format
   *
   * @param instant non-null Instant
   * @return an instance with sub-second component set to 0
   * @see <a href="">RCF 7519 § 2. Terminology</a>
   */
  private static Instant removeSubseconds(Instant instant) {
    return instant.with(ChronoField.MILLI_OF_SECOND, 0L);
  }

  public JwtClaims setExpirationTime(Instant expirationTime) {
    this.expirationTime = removeSubseconds(expirationTime);
    return this;
  }

  public JwtClaims setNotBefore(Instant notBefore) {
    this.notBefore = removeSubseconds(notBefore);
    return this;
  }

  public JwtClaims setIssuedAt(Instant issuedAt) {
    this.issuedAt = removeSubseconds(issuedAt);
    return this;
  }

  @XmlTransient
  private static final Set<String> RESERVED_CLAIM_NAMES = Arrays.stream(JwtClaims.class.getDeclaredFields())
    .filter(field -> field.isAnnotationPresent(XmlElement.class))
    .flatMap(field -> Arrays.stream(field.getAnnotationsByType(XmlElement.class)))
    .map(XmlElement::name)
    .collect(Collectors.toSet());

  @XmlTransient
  private static final XmlAdapterInstantLong DATE_ADAPTER = new XmlAdapterInstantLong();
  @XmlTransient
  private static final Class<?> UNMARSHALLING_CLASS = (new HashMap<String, Object>()).getClass();
  @XmlTransient
  private Map<String, Object> claims = new HashMap<>();

  /**
   * Create JWT Claims instance from JSON string
   *
   * @param json a valid JSON string representing JWT claims
   * @return A JwtClaims object
   * @throws IOException on json marshal error
   */
  @SuppressWarnings("unchecked")
  public static JwtClaims fromJson(String json) throws IOException {
    Map<String, Object> valueMap = (Map<String, Object>) JsonMarshaller.fromJson(json, UNMARSHALLING_CLASS);
    JwtClaims claims = new JwtClaims();
    claims.issuer = (String) valueMap.remove("iss");
    claims.subject = (String) valueMap.remove("sub");
    claims.audience = (String) valueMap.remove("aud");
    claims.jwtId = (String) valueMap.remove("jti");
    claims.expirationTime = convertToInstant(valueMap.remove("exp"));
    claims.notBefore = convertToInstant(valueMap.remove("nbf"));
    claims.issuedAt = convertToInstant(valueMap.remove("iat"));
    claims.claims = valueMap;

    return claims;
  }

  /**
   * Internal utility method for converting a value to Instant
   *
   * @param value
   * @return
   */
  private static Instant convertToInstant(Object value) {
    if (value == null) {
      return null;
    }
    if (value instanceof Integer) {
      return DATE_ADAPTER.unmarshal((long) (int) value);
    }
    if (value instanceof Long) {
      return DATE_ADAPTER.unmarshal((Long) value);
    }
    throw new IllegalArgumentException("Unsupported type for date field: " + value.getClass());
  }

  /**
   * Fluent method to add a claim with an arbitrary name that does not clash
   * with one of the standard claim names.
   *
   * @param claimName  claim name
   * @param claimValue claim value
   * @return this JwtClaims instance
   */
  public JwtClaims addClaim(String claimName, Object claimValue) {
    if (RESERVED_CLAIM_NAMES.contains(claimName)) {
      throw new IllegalArgumentException("Cannot use reserved claim name " + claimName);
    }
    claims.put(claimName, claimValue);
    return this;
  }

  public String getIssuer() {
    return this.issuer;
  }

  public JwtClaims setIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public String getSubject() {
    return this.subject;
  }

  public JwtClaims setSubject(String subject) {
    this.subject = subject;
    return this;
  }

  public String getAudience() {
    return this.audience;
  }

  public JwtClaims setAudience(String audience) {
    this.audience = audience;
    return this;
  }

  public Instant getExpirationTime() {
    return this.expirationTime;
  }

  public Instant getNotBefore() {
    return this.notBefore;
  }

  public Instant getIssuedAt() {
    return this.issuedAt;
  }

  public String getJwtId() {
    return this.jwtId;
  }

  public JwtClaims setJwtId(String jwtId) {
    this.jwtId = jwtId;
    return this;
  }

  public Map<String, Object> getClaims() {
    return this.claims;
  }

  public JwtClaims setClaims(Map<String, Object> claims) {
    this.claims = claims;
    return this;
  }

  @Override
  public String toJson() throws IOException {
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
    if (expirationTime != null) {
      jsonObject.put("exp", DATE_ADAPTER.marshal(expirationTime));
    }
    if (notBefore != null) {
      jsonObject.put("nbf", DATE_ADAPTER.marshal(notBefore));
    }
    if (issuedAt != null) {
      jsonObject.put("iat", DATE_ADAPTER.marshal(issuedAt));
    }
    if (jwtId != null) {
      jsonObject.put("jti", jwtId);
    }
    jsonObject.putAll(claims);
    return JsonMarshaller.toJson(jsonObject);
  }

  @Override
  public int hashCode() {
    int hash = 7;
    hash = 97 * hash + Objects.hashCode(this.issuer);
    hash = 97 * hash + Objects.hashCode(this.subject);
    hash = 97 * hash + Objects.hashCode(this.audience);
    hash = 97 * hash + Objects.hashCode(this.expirationTime);
    hash = 97 * hash + Objects.hashCode(this.notBefore);
    hash = 97 * hash + Objects.hashCode(this.issuedAt);
    hash = 97 * hash + Objects.hashCode(this.jwtId);
    hash = 97 * hash + Objects.hashCode(this.claims);
    return hash;
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
    if (!Objects.equals(this.expirationTime, other.expirationTime)) {
      return false;
    }
    if (!Objects.equals(this.notBefore, other.notBefore)) {
      return false;
    }
    if (!Objects.equals(this.issuedAt, other.issuedAt)) {
      return false;
    }
    return Objects.equals(this.claims, other.claims);
  }

}
