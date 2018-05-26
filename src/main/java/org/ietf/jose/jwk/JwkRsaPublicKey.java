package org.ietf.jose.jwk;

import org.ietf.jose.adapter.XmlAdapterBigIntegerBase64Url;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * RFC-7518 § 6.3.1. Parameters for RSA Public Keys
 * <p>
 * The following members MUST be present for RSA public keys.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwkRsaPublicKey extends JsonWebKey {

  /**
   * 6.3.1.1. "n" (Modulus) Parameter
   * <p>
   * The "n" (modulus) parameter contains the modulus value for the RSA public
   * key. It is represented as a Base64urlUInt-encoded value.
   * <p>
   * Note that implementers have found that some cryptographic libraries prefix
   * an extra zero-valued octet to the modulus representations they return, for
   * instance, returning 257 octets for a 2048-bit key, rather than 256.
   * Implementations using such libraries will need to take care to omit the
   * extra octet from the base64url-encoded representation.
   */
  @XmlElement(name = "n")
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  protected BigInteger modulus;

  /**
   * 6.3.1.2. "e" (Exponent) Parameter
   * <p>
   * The "e" (exponent) parameter contains the exponent value for the RSA public
   * key. It is represented as a Base64urlUInt-encoded value.
   * <p>
   * For instance, when representing the value 65537, the octet sequence to be
   * base64url-encoded MUST consist of the three octets [1, 0, 1]; the resulting
   * representation for this value is "AQAB".
   */
  @XmlElement(name = "e")
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  protected BigInteger publicExponent;

  public static JwkRsaPublicKey getInstance(RSAPublicKey publicKey) {
    JwkRsaPublicKey jwkRsaKey = new JwkRsaPrivateKey();
    jwkRsaKey.setPublicExponent(publicKey.getPublicExponent());
    jwkRsaKey.setModulus(publicKey.getModulus());
    return jwkRsaKey;
  }

  public BigInteger getModulus() {
    return modulus;
  }

  public void setModulus(BigInteger modulus) {
    this.modulus = modulus;
  }

  public BigInteger getPublicExponent() {
    return publicExponent;
  }

  public void setPublicExponent(BigInteger publicExponent) {
    this.publicExponent = publicExponent;
  }

  public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec spec = new RSAPublicKeySpec(getModulus(), getPublicExponent());
    return kf.generatePublic(spec);
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

    JwkRsaPublicKey that = (JwkRsaPublicKey) o;

    if (!modulus.equals(that.modulus)) {
      return false;
    }
    return publicExponent.equals(that.publicExponent);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + modulus.hashCode();
    result = 31 * result + publicExponent.hashCode();
    return result;
  }

  @Override
  public String toString() {
    return "JwkRsaPublicKey{"
      + "modulus=" + modulus
      + ", publicExponent=" + publicExponent
      + ", alg='" + alg + '\''
      + ", kid='" + kid + '\''
      + ", x5u=" + x5u
      + ", x5c=" + x5c
      + ", x5t='" + x5t + '\''
      + ", x5tS256='" + x5tS256 + '\''
      + '}';
  }
}
