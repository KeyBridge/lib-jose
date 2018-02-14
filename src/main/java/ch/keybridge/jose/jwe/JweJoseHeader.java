package ch.keybridge.jose.jwe;


import ch.keybridge.jose.JoseHeader;
import ch.keybridge.jose.adapter.XmlAdapterEContentEncryptionAlgorithm;
import ch.keybridge.jose.algorithm.EContentEncryptionAlgorithm;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
// omit the automatically added 'type' field in JSON output https://stackoverflow
// .com/questions/21091188/remove-type-from-json-output-jersey-moxy
public class JweJoseHeader extends JoseHeader {
  /**
   * 4.1.2.  "enc" (Encryption Algorithm) Header Parameter
   * <p>
   * The "enc" (encryption algorithm) Header Parameter identifies the
   * content encryption algorithm used to perform authenticated encryption
   * on the plaintext to produce the ciphertext and the Authentication
   * Tag.  This algorithm MUST be an AEAD algorithm with a specified key
   * length.  The encrypted content is not usable if the "enc" value does
   * not represent a supported algorithm.  "enc" values should either be
   * registered in the IANA "JSON Web Signature and Encryption Algorithms"
   * registry established by [JWA] or be a value that contains a
   * Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII
   * string containing a StringOrURI value.  This Header Parameter MUST be
   * present and MUST be understood and processed by implementations.
   * <p>
   * A list of defined "enc" values for this use can be found in the IANA
   * "JSON Web Signature and Encryption Algorithms" registry established
   * by [JWA]; the initial contents of this registry are the values
   * defined in Section 5.1 of [JWA].
   */
  @XmlElement(name = "enc")
  @XmlJavaTypeAdapter(type = EContentEncryptionAlgorithm.class, value = XmlAdapterEContentEncryptionAlgorithm.class)
  private EContentEncryptionAlgorithm contentEncryptionAlgorithm;

  @XmlElement(name = "zip")
  private String compressionAlgorithm;

  public EContentEncryptionAlgorithm getContentEncryptionAlgorithm() {
    return contentEncryptionAlgorithm;
  }

  public void setContentEncryptionAlgorithm(EContentEncryptionAlgorithm contentEncryptionAlgorithm) {
    this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    JweJoseHeader that = (JweJoseHeader) o;

    return contentEncryptionAlgorithm == that.contentEncryptionAlgorithm;
  }

  @Override
  public int hashCode() {
    return contentEncryptionAlgorithm != null ? contentEncryptionAlgorithm.hashCode() : 0;
  }
}