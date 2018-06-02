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
package org.ietf.jose.util;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwk.JsonWebKey;
import org.ietf.jose.jwk.key.EllipticCurveJwk;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;
import org.ietf.jose.jwk.key.SymmetricJwk;

/**
 * A utility class for common cryptographic operations
 */
public class CryptographyUtility {

  /**
   * Encrypt without any additional authenticated data
   *
   * @param payload payload bytes
   * @param key     Key
   * @param algo    JCA algorithm name for the Cipher
   * @return bytes returned by the Cipher. Always contains the ciphertext but
   *         may also contain appended authentication tag bytes.
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] encrypt(byte[] payload, Key key, String algo) throws GeneralSecurityException {
    return encrypt(payload, key, algo, null, null);
  }

  /**
   * Decrypt without any additional authenticated data
   *
   * @param ciphertext ciphertext bytes
   * @param key        Key
   * @param algo       JCA algorithm name for the Cipher
   * @return decrypted bytes returned by the Cipher.
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] decrypt(byte[] ciphertext, Key key, String algo) throws GeneralSecurityException {
    return decrypt(ciphertext, key, algo, null, null);
  }

  /**
   * Encrypt with additional algorithm specification and additional
   * authenticated data
   *
   * @param payload                      plaintext bytes
   * @param key                          key
   * @param algo                         JCA algorithm name for the Cipher
   * @param spec                         AlgorithmParameterSpec instance
   * @param additionalAuthenticationData bytes of additional authenticated data
   * @return bytes returned by the Cipher. Always contains the ciphertext but
   *         may also contain appended authentication tag bytes.
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] encrypt(byte[] payload, Key key, String algo, AlgorithmParameterSpec spec, byte[] additionalAuthenticationData) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    if (additionalAuthenticationData != null) {
      cipher.updateAAD(additionalAuthenticationData);
    }
    return cipher.doFinal(payload);
  }

  /**
   * Decrypt with additional algorithm specification and additional
   * authenticated data
   *
   * @param ciphertext                   ciphertext bytes
   * @param key                          key
   * @param algo                         JCA algorithm name for the Cipher
   * @param spec                         AlgorithmParameterSpec instance
   * @param additionalAuthenticationData bytes of additional authenticated data
   * @return bytes plaintext bytes.
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] decrypt(byte[] ciphertext, Key key, String algo, AlgorithmParameterSpec spec, byte[] additionalAuthenticationData) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.DECRYPT_MODE, key, spec);
    if (additionalAuthenticationData != null) {
      cipher.updateAAD(additionalAuthenticationData);
    }
    return cipher.doFinal(ciphertext);
  }

  /**
   * Wrap (encrypt) key.
   *
   * @param payloadKey a valid Key which will be wrapped (encrypted) using
   *                   another key
   * @param key        the wrapping/encryption key
   * @param algo       JCA algorithm name for the Cipher
   * @return ciphertext bytes
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] wrapKey(Key payloadKey, Key key, String algo) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.WRAP_MODE, key);
    return cipher.wrap(payloadKey);
  }

  /**
   *
   * Wrap (encrypt) key.
   *
   * @param payload ciphertext of the wrapped key
   * @param key     the wrapping/encryption key
   * @param algo    JCA algorithm name for the Cipher
   * @param keyAlgo JCA algorithm name for the key. E.g. for an AES SecretKey
   *                this would be "AES"
   * @return an unwrapped key
   * @throws GeneralSecurityException in case of failure
   */
  public static Key unwrapKey(byte[] payload, Key key, String algo, String keyAlgo) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.UNWRAP_MODE, key);
    return cipher.unwrap(payload, keyAlgo, Cipher.SECRET_KEY);
  }

  /**
   * Compute digital signature of a keyed message authentication (HMAC)
   *
   * @param payload data to sign
   * @param key     a valid key. Must be an instance of javax.crypto.SecretKey
   *                or java.security.PrivateKey
   * @param alg     JCA algorithm
   * @return bytes of the signature or HMAC
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] sign(byte[] payload, Key key, String alg) throws GeneralSecurityException {
    return key instanceof SecretKey
           ? sign(payload, (SecretKey) key, alg)
           : sign(payload, (PrivateKey) key, alg);
  }

  /**
   * Compute digital signature
   *
   * @param payload data to sign
   * @param key     a valid SecretKey instance
   * @param alg     JCA algorithm
   * @return signature bytes
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] sign(byte[] payload, SecretKey key, String alg) throws GeneralSecurityException {
    Mac mac = Mac.getInstance(alg);
    mac.init(key);
    return mac.doFinal(payload);
  }

  /**
   * Validate a keyed message authentication code (HMAC)
   *
   * @param signature signature bytes
   * @param payload   data that was signed
   * @param key       the secret (shared) key that was used to generate the HMAC
   * @param algorithm JCA algorithm
   * @return true if the signature or HMAC is valid
   * @throws GeneralSecurityException in case of failure
   */
  public static boolean validate(byte[] signature, byte[] payload, SecretKey key, String algorithm) throws GeneralSecurityException {
    Mac mac = Mac.getInstance(algorithm);
    mac.init(key);
    byte[] computedMac = mac.doFinal(payload);
    return Arrays.equals(signature, computedMac);
  }

  /**
   * Compute a keyed message authentication code (HMAC)
   *
   * @param payload data to sign
   * @param key     a valid SecretKey instance
   * @param alg     JCA algorithm
   * @return HMAC bytes
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] sign(byte[] payload, PrivateKey key, String alg) throws GeneralSecurityException {
    Signature signer = Signature.getInstance(alg);
    signer.initSign(key);
    signer.update(payload);
    return signer.sign();
  }

  /**
   * Validate a digital signature
   *
   * @param signature signature bytes
   * @param payload   data that was signed
   * @param key       the public key of the signing counter-party
   * @param algorithm JCA algorithm
   * @return true if the signature or HMAC is valid
   * @throws GeneralSecurityException in case of failure
   */
  public static boolean validate(byte[] signature, byte[] payload, PublicKey key, String algorithm) throws GeneralSecurityException {
    Signature sig = Signature.getInstance(algorithm);
    sig.initVerify(key);
    sig.update(payload);
    return sig.verify(signature);
  }

  /**
   * Compute digital signature of a keyed message authentication (HMAC)
   *
   * @param payloadBytes data to sign
   * @param jwk          JSON Web Key instance
   * @param algorithm    the JwsAlgorithmType
   * @return bytes of the signature or HMAC
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] sign(byte[] payloadBytes, JsonWebKey jwk, JwsAlgorithmType algorithm) throws
    GeneralSecurityException {
    if (jwk instanceof SymmetricJwk) {
      SymmetricJwk symmetricKey = (SymmetricJwk) jwk;
      String jcaAlgorithm = algorithm.getJavaAlgorithmName();
      return sign(payloadBytes, new SecretKeySpec(symmetricKey.getK(), jcaAlgorithm), jcaAlgorithm);
    } else if (jwk instanceof RsaPrivateJwk) {
      RsaPrivateJwk rsaKey = (RsaPrivateJwk) jwk;
      return sign(payloadBytes, rsaKey.getPrivateKey(), algorithm.getJavaAlgorithmName());
    } else if (jwk instanceof EllipticCurveJwk) {
      throw new UnsupportedOperationException("Elliptic curve keys are not supported");
    }
    throw new UnsupportedOperationException("Unsupported key type " + jwk.getClass().getCanonicalName());
  }

  /**
   * Validate digital signature of a keyed message authentication code (HMAC)
   *
   * @param signature signature bytes
   * @param payload   data used to create the signature
   * @param key       a valid key. Must be an instance of javax.crypto.SecretKey
   *                  or java.security.PrivateKey
   * @param algorithm JCA algorithm
   * @return true if the signature or HMAC is valid
   * @throws GeneralSecurityException in case of failure
   */
  public static boolean validateSignature(byte[] signature, byte[] payload, Key key, String algorithm) throws GeneralSecurityException {
    if (key instanceof SecretKey) {
      return validate(signature, payload, (SecretKey) key, algorithm);
    } else if (key instanceof PublicKey) {
      return validate(signature, payload, (PublicKey) key, algorithm);
    }
    return false;
  }

  /**
   * Validate digital signature of a keyed message authentication code (HMAC)
   * using a JSON Web Key
   *
   * @param signature signature bytes
   * @param payload   data used to create the signature
   * @param jwk       a valid JWK
   * @param algorithm JCA algorithm
   * @return TRUE if the signature is valid
   * @throws GeneralSecurityException in case of failure
   */
  public static boolean validateSignature(byte[] signature, byte[] payload, JsonWebKey jwk, String algorithm) throws
    GeneralSecurityException {
    if (jwk instanceof SymmetricJwk) {
      SymmetricJwk symmetricKey = (SymmetricJwk) jwk;
      SecretKey key = new SecretKeySpec(symmetricKey.getK(), algorithm);
      return validate(signature, payload, key, algorithm);
    } else if (jwk instanceof RsaPublicJwk) {
      RsaPublicJwk key = (RsaPublicJwk) jwk;
      return validate(signature, payload, key.getPublicKey(), algorithm);
    }
    return false;
  }
}
