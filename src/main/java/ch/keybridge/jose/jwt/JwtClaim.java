package ch.keybridge.jose.jwt;

import ch.keybridge.jose.adapter.XmlAdapterInstantLong;
import java.time.Instant;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * RFC 7519 § 4. JWT Claims
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
 * 4.1. Registered Claim Names The following Claim Names are registered in the
 * IANA "JSON Web Token Claims" registry established by Section 10.1. None of
 * the claims defined below are intended to be mandatory to use or implement in
 * all cases, but rather they provide a starting point for a set of useful,
 * interoperable claims. Applications using JWTs should define which specific
 * claims they use and when they are required or optional. All the names are
 * short because a core goal of JWTs is for the representation to be compact.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwtClaim {

  /**
   *
   * 4.1.1. "iss" (Issuer) Claim The "iss" (issuer) claim identifies the
   * principal that issued the JWT. The processing of this claim is generally
   * application specific. The "iss" value is a case-sensitive string containing
   * a StringOrURI value. Use of this claim is OPTIONAL.
   */
  @XmlElement(name = "iss")
  private String issuer;
  /**
   *
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
   *
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

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public String getAudience() {
    return audience;
  }

  public void setAudience(String audience) {
    this.audience = audience;
  }

  public Instant getExpirationTime() {
    return expirationTime;
  }

  public void setExpirationTime(Instant expirationTime) {
    this.expirationTime = expirationTime;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Instant notBefore) {
    this.notBefore = notBefore;
  }

  public Instant getIssuedAt() {
    return issuedAt;
  }

  public void setIssuedAt(Instant issuedAt) {
    this.issuedAt = issuedAt;
  }

  public String getJwtId() {
    return jwtId;
  }

  public void setJwtId(String jwtId) {
    this.jwtId = jwtId;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    JwtClaim jwtClaim = (JwtClaim) o;

    if (issuer != null ? !issuer.equals(jwtClaim.issuer) : jwtClaim.issuer != null) {
      return false;
    }
    if (subject != null ? !subject.equals(jwtClaim.subject) : jwtClaim.subject != null) {
      return false;
    }
    if (audience != null ? !audience.equals(jwtClaim.audience) : jwtClaim.audience != null) {
      return false;
    }
    if (expirationTime != null ? !expirationTime.equals(jwtClaim.expirationTime) : jwtClaim.expirationTime != null) {
      return false;
    }
    if (notBefore != null ? !notBefore.equals(jwtClaim.notBefore) : jwtClaim.notBefore != null) {
      return false;
    }
    if (issuedAt != null ? !issuedAt.equals(jwtClaim.issuedAt) : jwtClaim.issuedAt != null) {
      return false;
    }
    return jwtId != null ? jwtId.equals(jwtClaim.jwtId) : jwtClaim.jwtId == null;
  }

  @Override
  public int hashCode() {
    int result = issuer != null ? issuer.hashCode() : 0;
    result = 31 * result + (subject != null ? subject.hashCode() : 0);
    result = 31 * result + (audience != null ? audience.hashCode() : 0);
    result = 31 * result + (expirationTime != null ? expirationTime.hashCode() : 0);
    result = 31 * result + (notBefore != null ? notBefore.hashCode() : 0);
    result = 31 * result + (issuedAt != null ? issuedAt.hashCode() : 0);
    result = 31 * result + (jwtId != null ? jwtId.hashCode() : 0);
    return result;
  }
}
