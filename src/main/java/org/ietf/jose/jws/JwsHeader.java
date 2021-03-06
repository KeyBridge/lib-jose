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
package org.ietf.jose.jws;

import org.ietf.jose.AbstractHeader;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import org.ietf.jose.jwk.key.AbstractJwk;

/**
 * RFC 7515 JSON Web Signature (JWS)
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
 * <p>
 * A subtype of AbstractHeader which contains encryption-related fields used
 * across JWS and JWE.
 *
 * @see <a href="doc/jose-header.pdf">JOSE header type diagram</a>
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 02/01/2018
 */
public class JwsHeader extends AbstractHeader {

  /**
   * 4.1.2. "jku" (JWK Set URL) Header Parameter
   * <p>
   * The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that refers to
   * a resource for a set of JSON-encoded public keys, one of which corresponds
   * to the key used to digitally sign the JWS. The keys MUST be encoded as a
   * JWK Set [JWK]. The protocol used to acquire the resource MUST provide
   * integrity protection; an HTTP GET request to retrieve the JWK Set MUST use
   * Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the identity of the
   * server MUST be validated, as per Section 6 of RFC 6125 [RFC6125]. Also, see
   * Section 8 on TLS requirements. Use of this Header Parameter is OPTIONAL.
   */
  protected URI jku;
  /**
   * 4.1.3. "jwk" (JSON Web Key) Header Parameter
   * <p>
   * The "jwk" (JSON Web Key) Header Parameter is the public key that
   * corresponds to the key used to digitally sign the JWS. This key is
   * represented as a JSON Web Key [JWK]. Use of this Header Parameter is
   * OPTIONAL.
   */
  protected AbstractJwk jwk;
  /**
   * 4.1.9. "typ" (Type) Header Parameter
   * <p>
   * The "typ" (type) Header Parameter is used by JWS applications to declare
   * the media type [IANA.MediaTypes] of this complete JWS. This is intended for
   * use by the application when more than one kind of object could be present
   * in an application data structure that can contain a JWS; the application
   * can use this value to disambiguate among the different kinds of objects
   * that might be present. It will typically not be used by applications when
   * the kind of object is already known. This parameter is ignored by JWS
   * implementations; any processing of this parameter is performed by the JWS
   * application. Use of this Header Parameter is OPTIONAL.
   * <p>
   * Per RFC 2045 [RFC2045], all media type values, subtype values, and
   * parameter names are case insensitive. However, parameter values are case
   * sensitive unless otherwise specified for the specific parameter. To keep
   * messages compact in common situations, it is RECOMMENDED that producers
   * omit an "application/" prefix of a media type value in a "typ" Header
   * Parameter when no other ’/’ appears in the media type value. A recipient
   * using the media type value MUST treat it as if "application/" were
   * prepended to any "typ" value not containing a ’/’. For instance, a "typ"
   * value of "example" SHOULD be used to represent the "application/example"
   * media type, whereas the media type "application/example;part="1/2"" cannot
   * be shortened to "example;part="1/2"".
   * <p>
   * The "typ" value "JOSE" can be used by applications to indicate that this
   * object is a JWS or JWE using the JWS Compact Serialization or the JWE
   * Compact Serialization. The "typ" value "JOSE+JSON" can be used by
   * applications to indicate that this object is a JWS or JWE using the JWS
   * JSON Serialization or the JWE JSON Serialization. Other type values can
   * also be used by applications.
   */
  protected String typ;
  /**
   * 4.1.10. "cty" (Content Type) Header Parameter
   * <p>
   * The "cty" (content type) Header Parameter is used by JWS applications to
   * declare the media type [IANA.MediaTypes] of the secured content (the
   * payload). This is intended for use by the application when more than one
   * kind of object could be present in the JWS Payload; the application can use
   * this value to disambiguate among the different kinds of objects that might
   * be present. It will typically not be used by applications when the kind of
   * object is already known. This parameter is ignored by JWS implementations;
   * any processing of this parameter is performed by the JWS application. Use
   * of this Header Parameter is OPTIONAL.
   * <p>
   * Per RFC 2045 [RFC2045], all media type values, subtype values, and
   * parameter names are case insensitive. However, parameter values are case
   * sensitive unless otherwise specified for the specific parameter. To keep
   * messages compact in common situations, it is RECOMMENDED that producers
   * omit an "application/" prefix of a media type value in a "cty" Header
   * Parameter when no other ’/’ appears in the media type value. A recipient
   * using the media type value MUST treat it as if "application/" were
   * prepended to any "cty" value not containing a ’/’. For instance, a "cty"
   * value of "example" SHOULD be used to represent the "application/example"
   * media type, whereas the media type "application/example;part="1/2"" cannot
   * be shortened to "example;part="1/2"".
   */
  protected String cty;
  /**
   * 4.1.11. "crit" (Critical) Header Parameter
   * <p>
   * The "crit" (critical) Header Parameter indicates that extensions to this
   * specification and/or [JWA] are being used that MUST be understood and
   * processed. Its value is an array listing the Header Parameter names present
   * in the JOSE Header that use those extensions. If any of the listed
   * extension Header Parameters are not understood and supported by the
   * recipient, then the JWS is invalid. Producers MUST NOT include Header
   * Parameter names defined by this specification or [JWA] for use with JWS,
   * duplicate names, or names that do not occur as Header Parameter names
   * within the JOSE Header in the "crit" list. Producers MUST NOT use the empty
   * list "[]" as the "crit" value. Recipients MAY consider the JWS to be
   * invalid if the critical list contains any Header Parameter names defined by
   * this specification or [JWA] for use with JWS or if any other constraints on
   * its use are violated. When used, this Header Parameter MUST be integrity
   * private; therefore, it MUST occur only within the JWS Protected Header. Use
   * of this Header Parameter is OPTIONAL. This Header Parameter MUST be
   * understood and processed by implementations.
   * <p>
   * An example use, along with a hypothetical "exp" (expiration time) field is:
   * <pre>
   * {
   * "alg":"ES256",
   * "crit":["exp"],
   * "exp":1363284000
   * }
   * </pre>
   */
  protected List<String> crit;

  public JwsHeader() {
  }

  //<editor-fold defaultstate="collapsed" desc="Getter and Setter">
  public URI getJku() {
    return this.jku;
  }

  public void setJku(URI jku) {
    this.jku = jku;
  }

  public AbstractJwk getJwk() {
    return this.jwk;
  }

  public void setJwk(AbstractJwk jwk) {
    this.jwk = jwk;
  }

  public String getTyp() {
    return this.typ;
  }

  public void setTyp(String typ) {
    this.typ = typ;
  }

  public String getCty() {
    return this.cty;
  }

  public void setCty(String cty) {
    this.cty = cty;
  }

  public List<String> getCrit() {
    return this.crit;
  }

  public void setCrit(List<String> crit) {
    this.crit = crit;
  }//</editor-fold>

  @Override
  public int hashCode() {
    int hash = super.hashCode();
    hash = 59 * hash + Objects.hashCode(this.jku);
    hash = 59 * hash + Objects.hashCode(this.jwk);
    hash = 59 * hash + Objects.hashCode(this.typ);
    hash = 59 * hash + Objects.hashCode(this.cty);
    hash = 59 * hash + Objects.hashCode(this.crit);
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
    final JwsHeader other = (JwsHeader) obj;
    if (!Objects.equals(this.typ, other.typ)) {
      return false;
    }
    if (!Objects.equals(this.cty, other.cty)) {
      return false;
    }
    if (!Objects.equals(this.jku, other.jku)) {
      return false;
    }
    if (!Objects.equals(this.jwk, other.jwk)) {
      return false;
    }
    if (!Objects.equals(this.crit, other.crit)) {
      return false;
    }
    return super.equals(obj);
  }

}
