package org.ietf.jose.jwk;

import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.ietf.jose.adapter.XmlAdapterBigIntegerBase64Url;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 6.2. Parameters for Elliptic Curve Keys
 * <p>
 * JWKs can represent Elliptic Curve [DSS] keys. In this case, the "kty" member
 * value is "EC".
 * <p>
 * 6.2.1. Parameters for Elliptic Curve Public Keys
 * <p>
 * An Elliptic Curve public key is represented by a pair of coordinates drawn
 * from a finite field, which together define a point on an Elliptic Curve. The
 * following members MUST be present for all Elliptic Curve public keys: "crv",
 * "x"
 * <p>
 * 6.2.2. Parameters for Elliptic Curve Private Keys
 * <p>
 * In addition to the members used to represent Elliptic Curve public keys, the
 * following member MUST be present to represent Elliptic Curve private keys.
 * <p>
 * 6.2.2.1. "d" (ECC Private Key) Parameter
 *
 * @author Key Bridge
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class EcKey extends JWK {

  /**
   * 6.2.1.1. "crv" (Curve) Parameter
   * <p>
   * The "crv" (curve) parameter identifies the cryptographic curve used with
   * the key. Curve values from [DSS] used by this specification are:
   * <p>
   * "P-256", "P-384", "P-521"
   */
  private String crv;
  /**
   * 6.2.1.2. "x" (X Coordinate) Parameter
   * <p>
   * The "x" (x coordinate) parameter contains the x coordinate for the Elliptic
   * Curve point. It is represented as the base64url encoding of the octet
   * string representation of the coordinate, as defined in Section 2.3.5 of
   * SEC1 [SEC1]. The length of this octet string MUST be the full size of a
   * coordinate for the curve specified in the "crv" parameter. For example, if
   * the value of "crv" is "P-521", the octet string must be 66 octets long.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger x;
  /**
   * 6.2.1.3. "y" (Y Coordinate) Parameter
   * <p>
   * The "y" (y coordinate) parameter contains the y coordinate for the Elliptic
   * Curve point. It is represented as the base64url encoding of the octet
   * string representation of the coordinate, as defined in Section 2.3.5 of
   * SEC1 [SEC1]. The length of this octet string MUST be the full size of a
   * coordinate for the curve specified in the "crv" parameter. For example, if
   * the value of "crv" is "P-521", the octet string must be 66 octets long.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger y;
  /**
   * "d" (ECC Private Key) Parameter. MUST be present to represent Elliptic
   * Curve private keys
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
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
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    EcKey jwkEcKey = (EcKey) o;

    if (crv != null ? !crv.equals(jwkEcKey.crv) : jwkEcKey.crv != null) {
      return false;
    }
    if (x != null ? !x.equals(jwkEcKey.x) : jwkEcKey.x != null) {
      return false;
    }
    if (y != null ? !y.equals(jwkEcKey.y) : jwkEcKey.y != null) {
      return false;
    }
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
    return "JWKECPublicKey{"
      + "crv='" + crv + '\''
      + ", x=" + x
      + ", y=" + y
      + "} " + super.toString();
  }
}
