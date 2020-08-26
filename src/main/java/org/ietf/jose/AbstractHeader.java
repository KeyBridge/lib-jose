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
package org.ietf.jose;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import javax.json.bind.annotation.JsonbProperty;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jws.X5CHeaderParameter;

/**
 * An abstract JOSE header object. This is extended by JWS, JWE and JWK JOSE
 * implementations and includes fields common to each.
 * <pre>
 * 7515    7516     7517
 *  JWS     JWE      JWK       Header
 *  x        x        x        "alg" (Algorithm)
 *  x        x                 "crit" (Critical)
 *  x        x                 "cty" (Content Type)
 *           x                 "enc" (Encryption Algorithm)
 *  x        x                 "jku" (JWK Set URL)
 *  x        x                 "jwk" (JSON Web Key)
 *           x        x        "key_ops" (Key Operations)
 *  x        x        x        "kid" (Key ID)
 *                    x        "kty" (Key Type)
 *  x        x                 "typ" (Type)
 *                    x        "use" (Public Key Use)
 *  x        x        x        "x5c" (X.509 Certificate Chain)
 *  x        x        x        "x5t" (X.509 Certificate SHA-1 Thumbprint)
 *  x        x        x        "x5t#S256" (X.509 Certificate SHA-256 Thumbprint)
 *  x        x                 "x5u" (X.509 URL)
 *           x                 "zip" (Compression Algorithm) </pre>
 * <p>
 * RFC 7515 JSON Web Signature (JWS)
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
 * As indicated by the common registry, JWSs and JWEs share a common Header
 * Parameter space; when a parameter is used by both specifications, its usage
 * must be compatible between the specifications.
 * <p>
 * RFC 7517 JSON Web Key (JWK)
 * <p>
 * 4. JSON Web Key (JWK) Format
 * <p>
 * A JWK is a JSON object that represents a cryptographic key. The members of
 * the object represent properties of the key, including its value.
 * <p>
 * In addition to the common parameters, each JWK will have members that are key
 * type specific. These members represent the parameters of the key.
 * <p>
 * SeeAlso: JwsHeader, JweHeader, JsonWebKey
 */
// SeeAlso: JwsHeader, JweHeader, JsonWebKey
public abstract class AbstractHeader {

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
  protected List<X5CHeaderParameter> x5c;
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
  @JsonbProperty("x5t#S256")
  protected String x5tS256;

  public AbstractHeader() {
  }

  //<editor-fold defaultstate="collapsed" desc="Typed getters and setters for JWS and JWE algorithms">
  /**
   * Get the "alg" (Algorithm) Header Parameter. The parameter is typed per RFC
   * 7518 JSON Web Algorithms (JWA), (Algorithm) Header Parameter Values for
   * JWS.
   *
   * @return the "alg" (Algorithm) Header Parameter
   */
  public JwsAlgorithmType getJwsAlgorithmType() {
    return JwsAlgorithmType.resolveAlgorithm(alg);
  }

  public void setJwsAlgorithmType(JwsAlgorithmType alg) {
    this.alg = alg.getJoseAlgorithmName();
  }

  /**
   * Get the "alg" (Algorithm) Header Parameter. The parameter is typed per RFC
   * 7518 JSON Web Algorithms (JWA), (Algorithm) Header Parameter Values for
   * JWE.
   *
   * @return the "alg" (Algorithm) Header Parameter
   */
  public JweKeyAlgorithmType getJweKeyAlgorithmType() {
    return JweKeyAlgorithmType.resolveAlgorithm(alg);
  }

  public void setJwsAlgorithmType(JweKeyAlgorithmType alg) {
    this.alg = alg.getJoseAlgorithmName();
  }

  /**
   * Get the "alg" (Algorithm) Header Parameter. Use {@code getJwsAlgorithmType}
   * and {@code getJweKeyAlgorithmType} to get enumerated type instances of the
   * header.
   *
   * @return the "alg" (Algorithm) Header Parameter
   */
  public String getAlg() {
    return this.alg;
  }

  public void setAlg(String alg) {
    this.alg = alg;
  }

  public String getKid() {
    return this.kid;
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

  public List<X5CHeaderParameter> getX5c() {
    return this.x5c;
  }

  public void setX5c(List<X5CHeaderParameter> x5c) {
    this.x5c = x5c;
  }

  public String getX5t() {
    return this.x5t;
  }

  public void setX5t(String x5t) {
    this.x5t = x5t;
  }

  public String getX5tS256() {
    return this.x5tS256;
  }

  public void setX5tS256(String x5tS256) {
    this.x5tS256 = x5tS256;
  }//</editor-fold>

  /**
   * Inspect the other class to determine if this and the other class are the
   * same instance type.
   *
   * @param other the other class
   * @return TRUE if {@code this} is an instance of {@code other}
   */
  protected boolean canEqual(Object other) {
    return this.getClass().isInstance(other);
  }

  @Override
  public int hashCode() {
    int hash = 7;
    hash = 11 * hash + Objects.hashCode(this.alg);
    hash = 11 * hash + Objects.hashCode(this.kid);
    hash = 11 * hash + Objects.hashCode(this.x5u);
    hash = 11 * hash + Objects.hashCode(this.x5c);
    hash = 11 * hash + Objects.hashCode(this.x5t);
    hash = 11 * hash + Objects.hashCode(this.x5tS256);
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
    final AbstractHeader other = (AbstractHeader) obj;
    if (!Objects.equals(this.alg, other.alg)) {
      return false;
    }
    if (!Objects.equals(this.kid, other.kid)) {
      return false;
    }
    if (!Objects.equals(this.x5t, other.x5t)) {
      return false;
    }
    if (!Objects.equals(this.x5tS256, other.x5tS256)) {
      return false;
    }
    if (!Objects.equals(this.x5u, other.x5u)) {
      return false;
    }
    return Objects.equals(this.x5c, other.x5c);
  }

}
