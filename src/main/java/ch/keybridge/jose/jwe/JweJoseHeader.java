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
package ch.keybridge.jose.jwe;

import ch.keybridge.jose.JoseBase;
import ch.keybridge.jose.adapter.XmlAdapterEContentEncryptionAlgorithm;
import ch.keybridge.jose.jwe.encryption.EEncryptionAlgo;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlAccessorType(XmlAccessType.FIELD)
public class JweJoseHeader extends JoseBase {

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
  @XmlElement(name = "enc")
  @XmlJavaTypeAdapter(type = EEncryptionAlgo.class, value = XmlAdapterEContentEncryptionAlgorithm.class)
  private EEncryptionAlgo contentEncryptionAlgorithm;

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
  @XmlElement(name = "zip")
  private String compressionAlgorithm;

  public EEncryptionAlgo getContentEncryptionAlgorithm() {
    return contentEncryptionAlgorithm;
  }

  public void setContentEncryptionAlgorithm(EEncryptionAlgo contentEncryptionAlgorithm) {
    this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    JweJoseHeader that = (JweJoseHeader) o;

    return contentEncryptionAlgorithm == that.contentEncryptionAlgorithm;
  }

  @Override
  public int hashCode() {
    return contentEncryptionAlgorithm != null ? contentEncryptionAlgorithm.hashCode() : 0;
  }
}
