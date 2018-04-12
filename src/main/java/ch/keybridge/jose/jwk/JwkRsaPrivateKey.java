package ch.keybridge.jose.jwk;

import ch.keybridge.jose.adapter.XmlAdapterBigIntegerBase64Url;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * RFC-7518 § 6.3.2.  Parameters for RSA Private Keys
 * <p>
 * In addition to the members used to represent RSA public keys, the
 * following members are used to represent RSA private keys.  The
 * parameter "d" is REQUIRED for RSA private keys.  The others enable
 * optimizations and SHOULD be included by producers of JWKs
 * representing RSA private keys.  If the producer includes any of the
 * other private key parameters, then all of the others MUST be present,
 * with the exception of "oth", which MUST only be present when more
 * than two prime factors were used.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwkRsaPrivateKey extends JwkRsaPublicKey {
  /**
   * 6.3.2.1.  "d" (Private Exponent) Parameter
   * <p>
   * The "d" (private exponent) parameter contains the private exponent
   * value for the RSA private key.  It is represented as a Base64urlUInt-
   * encoded value.
   */
  @XmlElement(name = "d")
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger privateExponent;

  /**
   * 6.3.2.2.  "p" (First Prime Factor) Parameter
   * <p>
   * The "p" (first prime factor) parameter contains the first prime
   * factor.  It is represented as a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger p;

  /**
   * 6.3.2.3.  "q" (Second Prime Factor) Parameter
   * <p>
   * The "q" (second prime factor) parameter contains the second prime
   * factor.  It is represented as a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger q;

  /**
   * 6.3.2.4.  "dp" (First Factor CRT Exponent) Parameter
   * <p>
   * The "dp" (first factor CRT exponent) parameter contains the Chinese
   * Remainder Theorem (CRT) exponent of the first factor.  It is
   * represented as a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger dp;

  /**
   * 6.3.2.5.  "dq" (Second Factor CRT Exponent) Parameter
   * <p>
   * The "dq" (second factor CRT exponent) parameter contains the CRT
   * exponent of the second factor.  It is represented as a Base64urlUInt-
   * encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger dq;

  /**
   * 6.3.2.6.  "qi" (First CRT Coefficient) Parameter
   * <p>
   * The "qi" (first CRT coefficient) parameter contains the CRT
   * coefficient of the second factor.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger qi;

  /**
   * Developer note: the "oth" field is not supported.
   * <p>
   * 6.3.2.7.  "oth" (Other Primes Info) Parameter
   * <p>
   * The "oth" (other primes info) parameter contains an array of
   * information about any third and subsequent primes, should they exist.
   * When only two primes have been used (the normal case), this parameter
   * MUST be omitted.  When three or more primes have been used, the
   * number of array elements MUST be the number of primes used minus two.
   * For more information on this case, see the description of the
   * OtherPrimeInfo parameters in Appendix A.1.2 of RFC 3447 [RFC3447],
   * upon which the following parameters are modeled.  If the consumer of
   * a JWK does not support private keys with more than two primes and it
   * encounters a private key that includes the "oth" parameter, then it
   * MUST NOT use the key.  Each array element MUST be an object with the
   * following members.
   * <p>
   * 6.3.2.7.  "oth" (Other Primes Info) Parameter
   * <p>
   * The "oth" (other primes info) parameter contains an array of
   * information about any third and subsequent primes, should they exist.
   * When only two primes have been used (the normal case), this parameter
   * MUST be omitted.  When three or more primes have been used, the
   * number of array elements MUST be the number of primes used minus two.
   * For more information on this case, see the description of the
   * OtherPrimeInfo parameters in Appendix A.1.2 of RFC 3447 [RFC3447],
   * upon which the following parameters are modeled.  If the consumer of
   * a JWK does not support private keys with more than two primes and it
   * encounters a private key that includes the "oth" parameter, then it
   * MUST NOT use the key.  Each array element MUST be an object with the
   * following members.
   * <p>
   * 6.3.2.7.1.  "r" (Prime Factor)
   * <p>
   * The "r" (prime factor) parameter within an "oth" array member
   * represents the value of a subsequent prime factor.  It is represented
   * as a Base64urlUInt-encoded value.
   * <p>
   * 6.3.2.7.2.  "d" (Factor CRT Exponent)
   * <p>
   * The "d" (factor CRT exponent) parameter within an "oth" array member
   * represents the CRT exponent of the corresponding prime factor.  It is
   * represented as a Base64urlUInt-encoded value.
   * <p>
   * 6.3.2.7.3.  "t" (Factor CRT Coefficient)
   * <p>
   * The "t" (factor CRT coefficient) parameter within an "oth" array
   * member represents the CRT coefficient of the corresponding prime
   * factor.  It is represented as a Base64urlUInt-encoded value.
   */

  public static JwkRsaPrivateKey getInstance(KeyPair keyPair) {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    JwkRsaPrivateKey jwkRsaKey = new JwkRsaPrivateKey();
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

  public BigInteger getPrivateExponent() {
    return privateExponent;
  }

  public void setPrivateExponent(BigInteger privateExponent) {
    this.privateExponent = privateExponent;
  }

  public BigInteger getP() {
    return p;
  }

  public void setP(BigInteger p) {
    this.p = p;
  }

  public BigInteger getQ() {
    return q;
  }

  public void setQ(BigInteger q) {
    this.q = q;
  }

  public BigInteger getDp() {
    return dp;
  }

  public void setDp(BigInteger dp) {
    this.dp = dp;
  }

  public BigInteger getDq() {
    return dq;
  }

  public void setDq(BigInteger dq) {
    this.dq = dq;
  }

  public BigInteger getQi() {
    return qi;
  }

  public void setQi(BigInteger qi) {
    this.qi = qi;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    if (!super.equals(o)) return false;

    JwkRsaPrivateKey rsaKey = (JwkRsaPrivateKey) o;

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

  public boolean hasPrivateKey() {
    return privateExponent != null;
  }

  public PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKeySpec spec = new RSAPrivateKeySpec(getModulus(), getPrivateExponent());

    return kf.generatePrivate(spec);
  }

  public KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return new KeyPair(kf.generatePublic(new RSAPublicKeySpec(getModulus(), getPublicExponent())),
        kf.generatePrivate(new RSAPrivateKeySpec(getModulus(), getPrivateExponent())));
  }
}
