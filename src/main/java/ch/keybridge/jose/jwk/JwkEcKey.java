package ch.keybridge.jose.jwk;

import ch.keybridge.jose.adapter.XmlAdapterBigIntegerBase64Url;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.math.BigInteger;

@XmlAccessorType(XmlAccessType.FIELD)
public class JwkEcKey extends JsonWebKey {
  private String crv;
  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger x;
  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger y;
  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger d;

  public String getCrv() {
    return crv;
  }

  public void setCrv(String crv) {
    this.crv = crv;
  }

  public BigInteger getX() {
    return x;
  }

  public void setX(BigInteger x) {
    this.x = x;
  }

  public BigInteger getY() {
    return y;
  }

  public void setY(BigInteger y) {
    this.y = y;
  }

  public BigInteger getD() {
    return d;
  }

  public void setD(BigInteger d) {
    this.d = d;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    if (!super.equals(o)) return false;

    JwkEcKey jwkEcKey = (JwkEcKey) o;

    if (crv != null ? !crv.equals(jwkEcKey.crv) : jwkEcKey.crv != null) return false;
    if (x != null ? !x.equals(jwkEcKey.x) : jwkEcKey.x != null) return false;
    if (y != null ? !y.equals(jwkEcKey.y) : jwkEcKey.y != null) return false;
    return d != null ? d.equals(jwkEcKey.d) : jwkEcKey.d == null;
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + (crv != null ? crv.hashCode() : 0);
    result = 31 * result + (x != null ? x.hashCode() : 0);
    result = 31 * result + (y != null ? y.hashCode() : 0);
    result = 31 * result + (d != null ? d.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "JWKECPublicKey{" +
        "crv='" + crv + '\'' +
        ", x=" + x +
        ", y=" + y +
        "} " + super.toString();
  }
}
