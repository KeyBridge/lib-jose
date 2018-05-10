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
package ch.keybridge.jose;

import ch.keybridge.jose.adapter.XmlAdapterX509Certificate;
import ch.keybridge.jose.jwk.WktX509Certificate;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.net.URI;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * RFC7515 §4.
 * <p>
 * JOSE Header
 * <p>
 * For a JWS, the members of the JSON object(s) representing the JOSE Header
 * describe the digital signature or MAC applied to the JWS Protected Header and
 * the JWS Payload and optionally additional properties of the JWS. The Header
 * Parameter names within the JOSE Header MUST be unique; JWS parsers MUST
 * either reject JWSs with duplicate Header Parameter names or use a JSON parser
 * that returns only the lexically last duplicate member name, as specified in
 * Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].
 * <p>
 * Implementations are required to understand the specific Header Parameters
 * defined by this specification that are designated as "MUST be understood" and
 * process them in the manner defined in this specification. All other Header
 * Parameters defined by this specification that are not so designated MUST be
 * ignored when not understood. Unless listed as a critical Header Parameter,
 * per Section 4.1.11, all Header Parameters not defined by this specification
 * MUST be ignored when not understood.
 * <p>
 * There are three classes of Header Parameter names: Registered Header
 * Parameter names, Public Header Parameter names, and Private Header Parameter
 * names.
 * <p>
 * 4.1. Registered Header Parameter Names
 * <p>
 * The following Header Parameter names for use in JWSs are registered in the
 * IANA "JSON Web Signature and Encryption Header Parameters" registry
 * established by Section 9.1, with meanings as defined in the subsections
 * below.
 * <p>
 * As indicated by the common registry, JWSs and JWEs share a common Header
 * Parameter space; when a parameter is used by both specifications, its usage
 * must be compatible between the specifications.
 */
@XmlAccessorType(XmlAccessType.FIELD)
/**
 * Developer note: t
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class JoseBase {

  /**
   * 4.1.1. "alg" (Algorithm) Header Parameter
   * <p>
   * The "alg" (algorithm) Header Parameter identifies the cryptographic
   * algorithm used to secure the JWS. The JWS Signature value is not valid if
   * the "alg" value does not represent a supported algorithm or if there is not
   * a key for use with that algorithm associated with the party that digitally
   * signed or MACed the content. "alg" values should either be registered in
   * the IANA "JSON Web Signature and Encryption Algorithms" registry
   * established by [JWA] or be a value that contains a Collision-Resistant
   * Name. The "alg" value is a case- sensitive ASCII string containing a
   * StringOrURI value. This Header Parameter MUST be present and MUST be
   * understood and processed by implementations.
   * <p>
   * A list of defined "alg" values for this use can be found in the IANA "JSON
   * Web Signature and Encryption Algorithms" registry established by [JWA]; the
   * initial contents of this registry are the values defined in Section 3.1 of
   * [JWA].
   */
  protected String alg;
  /**
   * 4.1.4. "kid" (Key ID) Header Parameter
   * <p>
   * The "kid" (key ID) Header Parameter is a hint indicating which key was used
   * to secure the JWS. This parameter allows originators to explicitly signal a
   * change of key to recipients. The structure of the "kid" value is
   * unspecified. Its value MUST be a case-sensitive string. Use of this Header
   * Parameter is OPTIONAL. When used with a JWK, the "kid" value is used to
   * match a JWK "kid" parameter value.
   */
  protected String kid;
  /**
   * 4.1.5. "x5u" (X.509 URL) Header Parameter
   * <p>
   * The "x5u" (X.509 URL) Header Parameter is a URI [RFC3986] that refers to a
   * resource for the X.509 public key certificate or certificate chain
   * [RFC5280] corresponding to the key used to digitally sign the JWS. The
   * identified resource MUST provide a representation of the certificate or
   * certificate chain that conforms to RFC 5280 [RFC5280] in PEM-encoded form,
   * with each certificate delimited as specified in Section 6.1 of RFC 4945
   * [RFC4945]. The certificate containing the public key corresponding to the
   * key used to digitally sign the JWS MUST be the first certificate. This MAY
   * be followed by additional certificates, with each subsequent certificate
   * being the one used to certify the previous one. The protocol used to
   * acquire the resource MUST provide integrity protection; an HTTP GET request
   * to retrieve the certificate MUST use TLS [RFC2818] [RFC5246]; and the
   * identity of the server MUST be validated, as per Section 6 of RFC 6125
   * [RFC6125]. Also, see Section 8 on TLS requirements. Use of this Header
   * Parameter is OPTIONAL.
   */
  protected URI x5u;
  /**
   * 4.1.6. "x5c" (X.509 Certificate Chain) Header Parameter
   * <p>
   * The "x5c" (X.509 certificate chain) Header Parameter contains the X.509
   * public key certificate or certificate chain [RFC5280] corresponding to the
   * key used to digitally sign the JWS. The certificate or certificate chain is
   * represented as a JSON array of certificate value strings. Each string in
   * the array is a base64-encoded (Section 4 of [RFC4648] -- not
   * base64url-encoded) DER [ITU.X690.2008] PKIX certificate value. The
   * certificate containing the public key corresponding to the key used to
   * digitally sign the JWS MUST be the first certificate. This MAY be followed
   * by additional certificates, with each subsequent certificate being the one
   * used to certify the previous one. The recipient MUST validate the
   * certificate chain according to RFC 5280 [RFC5280] and consider the
   * certificate or certificate chain to be invalid if any validation failure
   * occurs. Use of this Header Parameter is OPTIONAL.
   */
  @XmlJavaTypeAdapter(type = WktX509Certificate.class, value = XmlAdapterX509Certificate.class)
  protected List<WktX509Certificate> x5c;
  /**
   * 4.1.7. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
   * <p>
   * The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
   * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of
   * the X.509 certificate [RFC5280] corresponding to the key used to digitally
   * sign the JWS. Note that certificate thumbprints are also sometimes known as
   * certificate fingerprints. Use of this Header Parameter is OPTIONAL.
   */
  protected String x5t;
  /**
   * 4.1.8. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter
   * <p>
   * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header Parameter is a
   * base64url-encoded SHA-256 thumbprint (a.k.a. digest) T to the key used to
   * digitally sign the JWS. Note that certificate thumbprints are also
   * sometimes known as certificate fingerprints. Use of this Header Parameter
   * is OPTIONAL.
   */
  @XmlElement(name = "x5t#S256")
  protected String x5tS256;

  public String getAlg() {
    return alg;
  }

  public void setAlg(String alg) {
    this.alg = alg;
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

  public String getX5tS256() {
    return x5tS256;
  }

  public void setX5tS256(String x5tS256) {
    this.x5tS256 = x5tS256;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    JoseBase that = (JoseBase) o;

    if (alg != null ? !alg.equals(that.alg) : that.alg != null) {
      return false;
    }
    if (kid != null ? !kid.equals(that.kid) : that.kid != null) {
      return false;
    }
    if (x5u != null ? !x5u.equals(that.x5u) : that.x5u != null) {
      return false;
    }
    if (x5c != null ? !x5c.equals(that.x5c) : that.x5c != null) {
      return false;
    }
    if (x5t != null ? !x5t.equals(that.x5t) : that.x5t != null) {
      return false;
    }
    return x5tS256 != null ? x5tS256.equals(that.x5tS256) : that.x5tS256 == null;
  }

  @Override
  public int hashCode() {
    int result = alg != null ? alg.hashCode() : 0;
    result = 31 * result + (kid != null ? kid.hashCode() : 0);
    result = 31 * result + (x5u != null ? x5u.hashCode() : 0);
    result = 31 * result + (x5c != null ? x5c.hashCode() : 0);
    result = 31 * result + (x5t != null ? x5t.hashCode() : 0);
    result = 31 * result + (x5tS256 != null ? x5tS256.hashCode() : 0);
    return result;
  }
}
