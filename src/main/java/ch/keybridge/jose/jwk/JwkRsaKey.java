package ch.keybridge.jose.jwk;

import ch.keybridge.jose.adapter.XmlAdapterBigIntegerBase64Url;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlDiscriminatorValue("RSA")
public class JwkRsaKey extends JWK implements Key {

  @XmlElement(name = "n")
  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger modulus;

  @XmlElement(name = "e")
  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger publicExponent;

  @XmlElement(name = "d")
  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger privateExponent;

  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger p;

  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger q;

  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger dp;

  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger dq;

  @XmlJavaTypeAdapter(type=BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger qi;

  public BigInteger getModulus() {
    return modulus;
  }

  public BigInteger getPublicExponent() {
    return publicExponent;
  }

  public BigInteger getPrivateExponent() {
    return privateExponent;
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getQ() {
    return q;
  }

  public BigInteger getDp() {
    return dp;
  }

  public BigInteger getDq() {
    return dq;
  }

  public BigInteger getQi() {
    return qi;
  }

  public void setModulus(BigInteger modulus) {
    this.modulus = modulus;
  }

  public void setPublicExponent(BigInteger publicExponent) {
    this.publicExponent = publicExponent;
  }

  public void setPrivateExponent(BigInteger privateExponent) {
    this.privateExponent = privateExponent;
  }

  public void setP(BigInteger p) {
    this.p = p;
  }

  public void setQ(BigInteger q) {
    this.q = q;
  }

  public void setDp(BigInteger dp) {
    this.dp = dp;
  }

  public void setDq(BigInteger dq) {
    this.dq = dq;
  }

  public void setQi(BigInteger qi) {
    this.qi = qi;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    if (!super.equals(o)) return false;

    JwkRsaKey rsaKey = (JwkRsaKey) o;

    if (modulus != null ? !modulus.equals(rsaKey.modulus) : rsaKey.modulus != null)
      return false;
    if (publicExponent != null ? !publicExponent.equals(rsaKey.publicExponent) : rsaKey.publicExponent != null)
      return false;
    if (privateExponent != null ? !privateExponent.equals(rsaKey.privateExponent) : rsaKey.privateExponent != null)
      return false;
    if (p != null ? !p.equals(rsaKey.p) : rsaKey.p != null) return false;
    if (q != null ? !q.equals(rsaKey.q) : rsaKey.q != null) return false;
    if (dp != null ? !dp.equals(rsaKey.dp) : rsaKey.dp != null) return false;
    if (dq != null ? !dq.equals(rsaKey.dq) : rsaKey.dq != null) return false;
    return qi != null ? qi.equals(rsaKey.qi) : rsaKey.qi == null;
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + (modulus != null ? modulus.hashCode() : 0);
    result = 31 * result + (publicExponent != null ? publicExponent.hashCode() : 0);
    result = 31 * result + (privateExponent != null ? privateExponent.hashCode() : 0);
    result = 31 * result + (p != null ? p.hashCode() : 0);
    result = 31 * result + (q != null ? q.hashCode() : 0);
    result = 31 * result + (dp != null ? dp.hashCode() : 0);
    result = 31 * result + (dq != null ? dq.hashCode() : 0);
    result = 31 * result + (qi != null ? qi.hashCode() : 0);
    return result;
  }

  @Override
  public boolean hasPrivateKey() {
    return privateExponent != null;
  }

  @Override
  public PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKeySpec spec = new RSAPrivateKeySpec(getModulus(), getPrivateExponent());

    return kf.generatePrivate(spec);
  }

  @Override
  public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec spec = new RSAPublicKeySpec(getModulus(), getPublicExponent());
    return kf.generatePublic(spec);
  }

  @Override
  public KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return new KeyPair(kf.generatePublic(new RSAPublicKeySpec(getModulus(), getPublicExponent())),
        kf.generatePrivate(new RSAPrivateKeySpec(getModulus(), getPrivateExponent())));
  }

  public static JwkRsaKey getInstance(KeyPair keyPair) {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    JwkRsaKey jwkRsaKey = new JwkRsaKey();
    jwkRsaKey.setPublicExponent(publicKey.getPublicExponent());
    jwkRsaKey.setModulus(publicKey.getModulus());
    jwkRsaKey.setPrivateExponent(privateKey.getPrivateExponent());
    jwkRsaKey.setAlg(privateKey.getAlgorithm());
    if (privateKey instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
      jwkRsaKey.setP(rsaPrivateCrtKey.getPrimeP());
      jwkRsaKey.setQ(rsaPrivateCrtKey.getPrimeQ());
      jwkRsaKey.setDp(rsaPrivateCrtKey.getPrimeExponentP());
      jwkRsaKey.setDq(rsaPrivateCrtKey.getPrimeExponentQ());
      jwkRsaKey.setQi(rsaPrivateCrtKey.getCrtCoefficient());
    }
    return jwkRsaKey;
  }
}
