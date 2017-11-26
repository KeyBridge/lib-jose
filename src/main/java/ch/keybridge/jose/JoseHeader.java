package ch.keybridge.jose;

import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.jwk.WktX509Certificate;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.net.URI;
import java.util.List;

/**
 * RFC7515 §4.
 * <p>
 * JOSE Header
 * <p>
 * For a JWS, the members of the JSON object(s) representing the JOSE
 * Header describe the digital signature or MAC applied to the JWS
 * Protected Header and the JWS Payload and optionally additional
 * properties of the JWS.  The Header Parameter names within the JOSE
 * Header MUST be unique; JWS parsers MUST either reject JWSs with
 * duplicate Header Parameter names or use a JSON parser that returns
 * only the lexically last duplicate member name, as specified in
 * Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].
 * <p>
 * Implementations are required to understand the specific Header
 * Parameters defined by this specification that are designated as "MUST
 * be understood" and process them in the manner defined in this
 * specification.  All other Header Parameters defined by this
 * specification that are not so designated MUST be ignored when not
 * understood.  Unless listed as a critical Header Parameter, per
 * Section 4.1.11, all Header Parameters not defined by this
 * specification MUST be ignored when not understood.
 * <p>
 * There are three classes of Header Parameter names: Registered Header
 * Parameter names, Public Header Parameter names, and Private Header
 * Parameter names.
 * <p>
 * 4.1.  Registered Header Parameter Names
 * <p>
 * The following Header Parameter names for use in JWSs are registered
 * in the IANA "JSON Web Signature and Encryption Header Parameters"
 * registry established by Section 9.1, with meanings as defined in the
 * subsections below.
 * <p>
 * As indicated by the common registry, JWSs and JWEs share a common
 * Header Parameter space; when a parameter is used by both
 * specifications, its usage must be compatible between the
 * specifications.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JoseHeader {
  /**
   * 4.1.1.  "alg" (Algorithm) Header Parameter
   * <p>
   * The "alg" (algorithm) Header Parameter identifies the cryptographic
   * algorithm used to secure the JWS.  The JWS Signature value is not
   * valid if the "alg" value does not represent a supported algorithm or
   * if there is not a key for use with that algorithm associated with the
   * party that digitally signed or MACed the content.  "alg" values
   * should either be registered in the IANA "JSON Web Signature and
   * Encryption Algorithms" registry established by [JWA] or be a value
   * that contains a Collision-Resistant Name.  The "alg" value is a case-
   * sensitive ASCII string containing a StringOrURI value.  This Header
   * Parameter MUST be present and MUST be understood and processed by
   * implementations.
   * <p>
   * A list of defined "alg" values for this use can be found in the IANA
   * "JSON Web Signature and Encryption Algorithms" registry established
   * by [JWA]; the initial contents of this registry are the values
   * defined in Section 3.1 of [JWA].
   */
  protected String alg;
  /**
   * 4.1.2.  "jku" (JWK Set URL) Header Parameter
   * <p>
   * The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
   * refers to a resource for a set of JSON-encoded public keys, one of
   * which corresponds to the key used to digitally sign the JWS.  The
   * keys MUST be encoded as a JWK Set [JWK].  The protocol used to
   * acquire the resource MUST provide integrity protection; an HTTP GET
   * request to retrieve the JWK Set MUST use Transport Layer Security
   * (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be
   * validated, as per Section 6 of RFC 6125 [RFC6125].  Also, see
   * Section 8 on TLS requirements.  Use of this Header Parameter is
   * OPTIONAL.
   */
  protected URI jku;
  /**
   * 4.1.3.  "jwk" (JSON Web Key) Header Parameter
   * <p>
   * The "jwk" (JSON Web Key) Header Parameter is the public key that
   * corresponds to the key used to digitally sign the JWS.  This key is
   * represented as a JSON Web Key [JWK].  Use of this Header Parameter is
   * OPTIONAL.
   */
  protected JWK jwk;
  /**
   * 4.1.4.  "kid" (Key ID) Header Parameter
   * <p>
   * The "kid" (key ID) Header Parameter is a hint indicating which key
   * was used to secure the JWS.  This parameter allows originators to
   * explicitly signal a change of key to recipients.  The structure of
   * the "kid" value is unspecified.  Its value MUST be a case-sensitive
   * string.  Use of this Header Parameter is OPTIONAL.
   * When used with a JWK, the "kid" value is used to match a JWK "kid"
   * parameter value.
   */
  protected String kid;
  /**
   * 4.1.5.  "x5u" (X.509 URL) Header Parameter
   * <p>
   * The "x5u" (X.509 URL) Header Parameter is a URI [RFC3986] that refers
   * to a resource for the X.509 public key certificate or certificate
   * chain [RFC5280] corresponding to the key used to digitally sign the
   * JWS.  The identified resource MUST provide a representation of the
   * certificate or certificate chain that conforms to RFC 5280 [RFC5280]
   * in PEM-encoded form, with each certificate delimited as specified in
   * Section 6.1 of RFC 4945 [RFC4945].  The certificate containing the
   * public key corresponding to the key used to digitally sign the JWS
   * MUST be the first certificate.  This MAY be followed by additional
   * certificates, with each subsequent certificate being the one used to
   * certify the previous one.  The protocol used to acquire the resource
   * MUST provide integrity protection; an HTTP GET request to retrieve
   * the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of
   * the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
   * Also, see Section 8 on TLS requirements.  Use of this Header
   * Parameter is OPTIONAL.
   */
  protected URI x5u;
  /**
   * 4.1.6.  "x5c" (X.509 Certificate Chain) Header Parameter
   * <p>
   * The "x5c" (X.509 certificate chain) Header Parameter contains the
   * X.509 public key certificate or certificate chain [RFC5280]
   * corresponding to the key used to digitally sign the JWS.  The
   * certificate or certificate chain is represented as a JSON array of
   * certificate value strings.  Each string in the array is a
   * base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
   * [ITU.X690.2008] PKIX certificate value.  The certificate containing
   * the public key corresponding to the key used to digitally sign the
   * JWS MUST be the first certificate.  This MAY be followed by
   * additional certificates, with each subsequent certificate being the
   * one used to certify the previous one.  The recipient MUST validate
   * the certificate chain according to RFC 5280 [RFC5280] and consider
   * the certificate or certificate chain to be invalid if any validation
   * failure occurs.  Use of this Header Parameter is OPTIONAL.
   */
  protected List<WktX509Certificate> x5c;
  /**
   * 4.1.7.  "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
   * <p>
   * The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
   * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
   * encoding of the X.509 certificate [RFC5280] corresponding to the key
   * used to digitally sign the JWS.  Note that certificate thumbprints
   * are also sometimes known as certificate fingerprints.  Use of this
   * Header Parameter is OPTIONAL.
   */
  protected String x5t;
  /**
   * 4.1.9.  "typ" (Type) Header Parameter
   * <p>
   * The "typ" (type) Header Parameter is used by JWS applications to
   * declare the media type [IANA.MediaTypes] of this complete JWS.  This
   * is intended for use by the application when more than one kind of
   * object could be present in an application data structure that can
   * contain a JWS; the application can use this value to disambiguate
   * among the different kinds of objects that might be present.  It will
   * typically not be used by applications when the kind of object is
   * already known.  This parameter is ignored by JWS implementations; any
   * processing of this parameter is performed by the JWS application.
   * Use of this Header Parameter is OPTIONAL.
   * <p>
   * Per RFC 2045 [RFC2045], all media type values, subtype values, and
   * parameter names are case insensitive.  However, parameter values are
   * case sensitive unless otherwise specified for the specific parameter.
   * To keep messages compact in common situations, it is RECOMMENDED that
   * producers omit an "application/" prefix of a media type value in a
   * "typ" Header Parameter when no other ’/’ appears in the media type
   * value.  A recipient using the media type value MUST treat it as if
   * "application/" were prepended to any "typ" value not containing a
   * ’/’.  For instance, a "typ" value of "example" SHOULD be used to
   * represent the "application/example" media type, whereas the media
   * type "application/example;part="1/2"" cannot be shortened to
   * "example;part="1/2"".
   * <p>
   * The "typ" value "JOSE" can be used by applications to indicate that
   * this object is a JWS or JWE using the JWS Compact Serialization or
   * the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
   * used by applications to indicate that this object is a JWS or JWE
   * using the JWS JSON Serialization or the JWE JSON Serialization.
   * Other type values can also be used by applications.
   */
  protected String typ;
  /**
   * 4.1.10.  "cty" (Content Type) Header Parameter
   * <p>
   * The "cty" (content type) Header Parameter is used by JWS applications
   * to declare the media type [IANA.MediaTypes] of the secured content
   * (the payload).  This is intended for use by the application when more
   * than one kind of object could be present in the JWS Payload; the
   * application can use this value to disambiguate among the different
   * kinds of objects that might be present.  It will typically not be
   * used by applications when the kind of object is already known.  This
   * parameter is ignored by JWS implementations; any processing of this
   * parameter is performed by the JWS application.  Use of this Header
   * Parameter is OPTIONAL.
   * <p>
   * Per RFC 2045 [RFC2045], all media type values, subtype values, and
   * parameter names are case insensitive.  However, parameter values are
   * case sensitive unless otherwise specified for the specific parameter.
   * To keep messages compact in common situations, it is RECOMMENDED that
   * producers omit an "application/" prefix of a media type value in a
   * "cty" Header Parameter when no other ’/’ appears in the media type
   * value.  A recipient using the media type value MUST treat it as if
   * "application/" were prepended to any "cty" value not containing a
   * ’/’.  For instance, a "cty" value of "example" SHOULD be used to
   * represent the "application/example" media type, whereas the media
   * type "application/example;part="1/2"" cannot be shortened to
   * "example;part="1/2"".
   */
  protected String cty;
  /**
   * 4.1.8.  "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
   * Parameter
   * <p>
   * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
   * Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
   T
   * to the key used to digitally sign the JWS.  Note that certificate
   * thumbprints are also sometimes known as certificate fingerprints.
   * Use of this Header Parameter is OPTIONAL.
   */
  @XmlElement(name = "x5t#S256")
  String x5tS256;
  /**
   * 4.1.11.  "crit" (Critical) Header Parameter
   *
   The "crit" (critical) Header Parameter indicates that extensions to
   this specification and/or [JWA] are being used that MUST be
   understood and processed.  Its value is an array listing the Header
   Parameter names present in the JOSE Header that use those extensions.
   If any of the listed extension Header Parameters are not understood
   and supported by the recipient, then the JWS is invalid.  Producers
   MUST NOT include Header Parameter names defined by this specification
   or [JWA] for use with JWS, duplicate names, or names that do not
   occur as Header Parameter names within the JOSE Header in the "crit"
   list.  Producers MUST NOT use the empty list "[]" as the "crit"
   value.  Recipients MAY consider the JWS to be invalid if the critical
   list contains any Header Parameter names defined by this
   specification or [JWA] for use with JWS or if any other constraints
   on its use are violated.  When used, this Header Parameter MUST be
   integrity protected; therefore, it MUST occur only within the JWS
   Protected Header.  Use of this Header Parameter is OPTIONAL.  This
   Header Parameter MUST be understood and processed by implementations.

   An example use, along with a hypothetical "exp" (expiration time)
   field is:
   <pre>
   {
   "alg":"ES256",
   "crit":["exp"],
   "exp":1363284000
   }
   </pre>
   */
  protected List<String> crit;

  public String getAlg() {
    return alg;
  }

  public void setAlg(String alg) {
    this.alg = alg;
  }

  public URI getJku() {
    return jku;
  }

  public void setJku(URI jku) {
    this.jku = jku;
  }

  public JWK getJwk() {
    return jwk;
  }

  public void setJwk(JWK jwk) {
    this.jwk = jwk;
  }

  public String getKid() {
    return kid;
  }

  public void setKid(String kid) {
    this.kid = kid;
  }

  public URI getX5u() {
    return x5u;
  }

  public void setX5u(URI x5u) {
    this.x5u = x5u;
  }

  public List<WktX509Certificate> getX5c() {
    return x5c;
  }

  public void setX5c(List<WktX509Certificate> x5c) {
    this.x5c = x5c;
  }

  public String getX5t() {
    return x5t;
  }

  public void setX5t(String x5t) {
    this.x5t = x5t;
  }

  public String getTyp() {
    return typ;
  }

  public void setTyp(String typ) {
    this.typ = typ;
  }

  public String getCty() {
    return cty;
  }

  public void setCty(String cty) {
    this.cty = cty;
  }

  public String getX5tS256() {
    return x5tS256;
  }

  public void setX5tS256(String x5tS256) {
    this.x5tS256 = x5tS256;
  }

  public List<String> getCrit() {
    return crit;
  }

  public void setCrit(List<String> crit) {
    this.crit = crit;
  }

  @Override
  public String toString() {
    return "JOSEHeader{" +
        "alg='" + alg + '\'' +
        ", jku=" + jku +
        ", jwk=" + jwk +
        ", kid='" + kid + '\'' +
        ", x5u=" + x5u +
        ", x5c=" + x5c +
        ", x5t='" + x5t + '\'' +
        ", typ='" + typ + '\'' +
        ", cty='" + cty + '\'' +
        ", x5tS256='" + x5tS256 + '\'' +
        ", crit=" + crit +
        '}';
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    JoseHeader that = (JoseHeader) o;

    if (alg != null ? !alg.equals(that.alg) : that.alg != null) return false;
    if (jku != null ? !jku.equals(that.jku) : that.jku != null) return false;
    if (jwk != null ? !jwk.equals(that.jwk) : that.jwk != null) return false;
    if (kid != null ? !kid.equals(that.kid) : that.kid != null) return false;
    if (x5u != null ? !x5u.equals(that.x5u) : that.x5u != null) return false;
    if (x5c != null ? !x5c.equals(that.x5c) : that.x5c != null) return false;
    if (x5t != null ? !x5t.equals(that.x5t) : that.x5t != null) return false;
    if (typ != null ? !typ.equals(that.typ) : that.typ != null) return false;
    if (cty != null ? !cty.equals(that.cty) : that.cty != null) return false;
    if (x5tS256 != null ? !x5tS256.equals(that.x5tS256) : that.x5tS256 != null) return false;
    return crit != null ? crit.equals(that.crit) : that.crit == null;
  }

  @Override
  public int hashCode() {
    int result = alg != null ? alg.hashCode() : 0;
    result = 31 * result + (jku != null ? jku.hashCode() : 0);
    result = 31 * result + (jwk != null ? jwk.hashCode() : 0);
    result = 31 * result + (kid != null ? kid.hashCode() : 0);
    result = 31 * result + (x5u != null ? x5u.hashCode() : 0);
    result = 31 * result + (x5c != null ? x5c.hashCode() : 0);
    result = 31 * result + (x5t != null ? x5t.hashCode() : 0);
    result = 31 * result + (typ != null ? typ.hashCode() : 0);
    result = 31 * result + (cty != null ? cty.hashCode() : 0);
    result = 31 * result + (x5tS256 != null ? x5tS256.hashCode() : 0);
    result = 31 * result + (crit != null ? crit.hashCode() : 0);
    return result;
  }
}
