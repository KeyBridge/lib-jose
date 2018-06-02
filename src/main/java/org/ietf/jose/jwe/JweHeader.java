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
package org.ietf.jose.jwe;

import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.ietf.jose.adapter.XmlAdapterEContentEncryptionAlgorithm;
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jws.AbstractHeader;

/**
 * RFC 7516 JSON Web Encryption (JWE)
 * <p>
 * 4. JOSE Header
 * <p>
 * For a JWE, the members of the JSON object(s) representing the JOSE Header
 * describe the encryption applied to the plaintext and optionally additional
 * properties of the JWE. The Header Parameter names within the JOSE Header MUST
 * be unique, just as described in Section 4 of [JWS]. The rules about handling
 * Header Parameters that are not understood by the implementation are also the
 * same. The classes of Header Parameter names are likewise the same.
 * <p>
 * 4.1. Registered Header Parameter Names
 * <pre>
 * 4.1.1.  "alg" (Algorithm)
 * 4.1.2.  "enc" (Encryption Algorithm)
 * 4.1.3.  "zip" (Compression Algorithm)
 * 4.1.4.  "jku" (JWK Set URL)
 * 4.1.5.  "jwk" (JSON Web Key)
 * 4.1.6.  "kid" (Key ID)
 * 4.1.7.  "x5u" (X.509 URL)
 * 4.1.8.  "x5c" (X.509 Certificate Chain)
 * 4.1.9.  "x5t" (X.509 Certificate SHA-1 Thumbprint)
 * 4.1.10. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint)
 * 4.1.11. "typ" (Type)
 * 4.1.12. "cty" (Content Type)
 * 4.1.13. "crit" (Critical)
 * </pre> 4.2. Public Header Parameter Names
 * <p>
 * Additional Header Parameter names can be defined by those using JWEs.
 * <p>
 * 4.3. Private Header Parameter Names
 * <p>
 * A producer and consumer of a JWE may agree to use Header Parameter names that
 * are Private Names: names that are not Registered Header Parameter names or
 * Public Header Parameter names.
 *
 * @author Key Bridge
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JweHeader extends AbstractHeader {

  /**
   * 4.1.2. "enc" (Encryption Algorithm) Header Parameter
   * <p>
   * The "enc" (encryption algorithm) Header Parameter identifies the content
   * encryption algorithm used to perform authenticated encryption on the
   * plaintext to produce the ciphertext and the Authentication Tag. This
   * algorithm MUST be an AEAD algorithm with a specified key length. The
   * encrypted content is not usable if the "enc" value does not represent a
   * supported algorithm. "enc" values should either be registered in the IANA
   * "JSON Web Signature and Encryption Algorithms" registry established by
   * [JWA] or be a value that contains a Collision-Resistant Name. The "enc"
   * value is a case-sensitive ASCII string containing a StringOrURI value. This
   * Header Parameter MUST be present and MUST be understood and processed by
   * implementations.
   * <p>
   * A list of defined "enc" values for this use can be found in the IANA "JSON
   * Web Signature and Encryption Algorithms" registry established by [JWA]; the
   * initial contents of this registry are the values defined in Section 5.1 of
   * [JWA].
   */
  @XmlJavaTypeAdapter(type = JweEncryptionAlgorithmType.class, value = XmlAdapterEContentEncryptionAlgorithm.class)
  private JweEncryptionAlgorithmType enc;

  /**
   * 4.1.3. "zip" (Compression Algorithm) Header Parameter
   * <p>
   * The "zip" (compression algorithm) applied to the plaintext before
   * encryption, if any. The "zip" value defined by this specification is:
   * <p>
   * o "DEF" - Compression with the DEFLATE [RFC1951] algorithm
   * <p>
   * Other values MAY be used. Compression algorithm values can be registered in
   * the IANA "JSON Web Encryption Compression Algorithms" registry established
   * by [JWA]. The "zip" value is a case-sensitive string. If no "zip" parameter
   * is present, no compression is applied to the plaintext before encryption.
   * When used, this Header Parameter MUST be integrity protected; therefore, it
   * MUST occur only within the JWE Protected Header. Use of this Header
   * Parameter is OPTIONAL. This Header Parameter MUST be understood and
   * processed by implementations.
   */
  private String zip;

  public JweHeader() {
  }

  public JweEncryptionAlgorithmType getEnc() {
    return this.enc;
  }

  public void setEnc(JweEncryptionAlgorithmType enc) {
    this.enc = enc;
  }

  public String getZip() {
    return this.zip;
  }

  public void setZip(String zip) {
    this.zip = zip;
  }

  @Override
  public String toString() {
    return "JweHeader(enc=" + this.getEnc() + ", zip=" + this.getZip() + ")";
  }

  @Override
  public int hashCode() {
    int hash = 7;
    hash = 71 * hash + Objects.hashCode(this.enc);
    hash = 71 * hash + Objects.hashCode(this.zip);
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
    final JweHeader other = (JweHeader) obj;
    if (!Objects.equals(this.zip, other.zip)) {
      return false;
    }
    return this.enc == other.enc;
  }

  @Override
  protected boolean canEqual(Object other) {
    return other instanceof JweHeader;
  }
}
