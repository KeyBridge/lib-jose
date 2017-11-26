package ch.keybridge.jose.jwk;

import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Arrays;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlDiscriminatorValue("oct")
public class JwkSymmetricKey extends JWK {

  @XmlJavaTypeAdapter(type=byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] k;

  public byte[] getK() {
    return k;
  }

  public void setK(byte[] k) {
    this.k = k;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    if (!super.equals(o)) return false;

    JwkSymmetricKey that = (JwkSymmetricKey) o;

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
    return "JwkSymmetricKey{" +
        "k=" + Arrays.toString(k) +
        '}';
  }
}
