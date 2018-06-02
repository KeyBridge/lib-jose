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
package org.ietf.jose.jwk.key;

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
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.ietf.jose.adapter.XmlAdapterBigIntegerBase64Url;

/**
 * RFC 7518 JSON Web Algorithms (JWA)
 * <p>
 * 6.3.2. Parameters for RSA Private Keys
 * <p>
 * In addition to the members used to represent RSA public keys, the following
 * members are used to represent RSA private keys. The parameter "d" is REQUIRED
 * for RSA private keys. The others enable optimizations and SHOULD be included
 * by producers of JWKs representing RSA private keys. If the producer includes
 * any of the other private key parameters, then all of the others MUST be
 * present, with the exception of "oth", which MUST only be present when more
 * than two prime factors were used.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class RsaPrivateJwk extends RsaPublicJwk {

  /**
   * 6.3.2.1. "d" (Private Exponent) Parameter
   * <p>
   * The "d" (private exponent) parameter contains the private exponent value
   * for the RSA private key. It is represented as a Base64urlUInt- encoded
   * value.
   */
  @XmlElement(name = "d")
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger privateExponent;

  /**
   * 6.3.2.2. "p" (First Prime Factor) Parameter
   * <p>
   * The "p" (first prime factor) parameter contains the first prime factor. It
   * is represented as a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger p;

  /**
   * 6.3.2.3. "q" (Second Prime Factor) Parameter
   * <p>
   * The "q" (second prime factor) parameter contains the second prime factor.
   * It is represented as a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger q;

  /**
   * 6.3.2.4. "dp" (First Factor CRT Exponent) Parameter
   * <p>
   * The "dp" (first factor CRT exponent) parameter contains the Chinese
   * Remainder Theorem (CRT) exponent of the first factor. It is represented as
   * a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger dp;

  /**
   * 6.3.2.5. "dq" (Second Factor CRT Exponent) Parameter
   * <p>
   * The "dq" (second factor CRT exponent) parameter contains the CRT exponent
   * of the second factor. It is represented as a Base64urlUInt- encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger dq;

  /**
   * 6.3.2.6. "qi" (First CRT Coefficient) Parameter
   * <p>
   * The "qi" (first CRT coefficient) parameter contains the CRT coefficient of
   * the second factor. It is represented as a Base64urlUInt-encoded value.
   */
  @XmlJavaTypeAdapter(type = BigInteger.class, value = XmlAdapterBigIntegerBase64Url.class)
  private BigInteger qi;

  public RsaPrivateJwk() {
  }

  /**
   * Developer note: the "oth" field is not supported.
   * <p>
   * 6.3.2.7. "oth" (Other Primes Info) Parameter
   * <p>
   * The "oth" (other primes info) parameter contains an array of information
   * about any third and subsequent primes, should they exist. When only two
   * primes have been used (the normal case), this parameter MUST be omitted.
   * When three or more primes have been used, the number of array elements MUST
   * be the number of primes used minus two. For more information on this case,
   * see the description of the OtherPrimeInfo parameters in Appendix A.1.2 of
   * RFC 3447 [RFC3447], upon which the following parameters are modeled. If the
   * consumer of a JWK does not support private keys with more than two primes
   * and it encounters a private key that includes the "oth" parameter, then it
   * MUST NOT use the key. Each array element MUST be an object with the
   * following members.
   * <p>
   * 6.3.2.7. "oth" (Other Primes Info) Parameter
   * <p>
   * The "oth" (other primes info) parameter contains an array of information
   * about any third and subsequent primes, should they exist. When only two
   * primes have been used (the normal case), this parameter MUST be omitted.
   * When three or more primes have been used, the number of array elements MUST
   * be the number of primes used minus two. For more information on this case,
   * see the description of the OtherPrimeInfo parameters in Appendix A.1.2 of
   * RFC 3447 [RFC3447], upon which the following parameters are modeled. If the
   * consumer of a JWK does not support private keys with more than two primes
   * and it encounters a private key that includes the "oth" parameter, then it
   * MUST NOT use the key. Each array element MUST be an object with the
   * following members.
   * <p>
   * 6.3.2.7.1. "r" (Prime Factor)
   * <p>
   * The "r" (prime factor) parameter within an "oth" array member represents
   * the value of a subsequent prime factor. It is represented as a
   * Base64urlUInt-encoded value.
   * <p>
   * 6.3.2.7.2. "d" (Factor CRT Exponent)
   * <p>
   * The "d" (factor CRT exponent) parameter within an "oth" array member
   * represents the CRT exponent of the corresponding prime factor. It is
   * represented as a Base64urlUInt-encoded value.
   * <p>
   * 6.3.2.7.3. "t" (Factor CRT Coefficient)
   * <p>
   * The "t" (factor CRT coefficient) parameter within an "oth" array member
   * represents the CRT coefficient of the corresponding prime factor. It is
   * represented as a Base64urlUInt-encoded value.
   *
   * @param keyPair a key pair (a public key and a private key).
   * @param keyId   the key id
   * @return a new RSA private key
   */
  public static RsaPrivateJwk getInstance(KeyPair keyPair, String keyId) {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RsaPrivateJwk jwkRsaKey = new RsaPrivateJwk();
    jwkRsaKey.setPublicExponent(publicKey.getPublicExponent());
    jwkRsaKey.setModulus(publicKey.getModulus());
    jwkRsaKey.setPrivateExponent(privateKey.getPrivateExponent());
    jwkRsaKey.setAlg(privateKey.getAlgorithm());
    jwkRsaKey.setKid(keyId);
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

  public BigInteger getPrivateExponent() {
    return this.privateExponent;
  }

  public void setPrivateExponent(BigInteger privateExponent) {
    this.privateExponent = privateExponent;
  }

  public BigInteger getP() {
    return this.p;
  }

  public void setP(BigInteger p) {
    this.p = p;
  }

  public BigInteger getQ() {
    return this.q;
  }

  public void setQ(BigInteger q) {
    this.q = q;
  }

  public BigInteger getDp() {
    return this.dp;
  }

  public void setDp(BigInteger dp) {
    this.dp = dp;
  }

  public BigInteger getDq() {
    return this.dq;
  }

  public void setDq(BigInteger dq) {
    this.dq = dq;
  }

  public BigInteger getQi() {
    return this.qi;
  }

  public void setQi(BigInteger qi) {
    this.qi = qi;
  }

}
