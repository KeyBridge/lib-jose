package org.ietf.jose.jwk.key;

import java.util.Arrays;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.jwk.JWK;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 6.4. Parameters for Symmetric Keys
 * <p>
 * When the JWK "kty" member value is "oct" (octet sequence), the member "k"
 * (see Section 6.4.1) is used to represent a symmetric key (or another key
 * whose value is a single octet sequence). An "alg" member SHOULD also be
 * present to identify the algorithm intended to be used with the key, unless
 * the application uses another means or convention to determine the algorithm
 * used.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class SymmetricKey extends JWK {

  /**
   * 6.4.1. "k" (Key Value) Parameter
   * <p>
   * The "k" (key value) parameter contains the value of the symmetric (or other
   * single-valued) key. It is represented as the base64url encoding of the
   * octet sequence containing the key value.
   */
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] k;

  public byte[] getK() {
    return k;
  }

  public void setK(byte[] k) {
    this.k = k;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    SymmetricKey that = (SymmetricKey) o;

    return Arrays.equals(k, that.k);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + Arrays.hashCode(k);
    return result;
  }

  @Override
  public String
    toString() {
    return "JwkSymmetricKey{"
      + "k=" + Arrays.toString(k)
      + '}';
  }
}
