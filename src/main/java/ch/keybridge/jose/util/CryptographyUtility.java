package ch.keybridge.jose.util;

import ch.keybridge.jose.jwk.JsonWebKey;
import ch.keybridge.jose.jwk.JwkEcKey;
import ch.keybridge.jose.jwk.JwkRsaPrivateKey;
import ch.keybridge.jose.jwk.JwkSymmetricKey;
import ch.keybridge.jose.jws.ESignatureAlgorithm;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
   * @return bytes of the signature or HMAC
   * @throws GeneralSecurityException in case of failure
   */
  public static byte[] sign(byte[] payloadBytes, JsonWebKey jwk) throws GeneralSecurityException {
    final ESignatureAlgorithm algorithm = ESignatureAlgorithm.resolveAlgorithm(jwk.getAlg());
    if (jwk instanceof JwkSymmetricKey) {
      JwkSymmetricKey symmetricKey = (JwkSymmetricKey) jwk;
      return sign(payloadBytes, new SecretKeySpec(symmetricKey.getK(), algorithm.getJavaAlgorithmName()), algorithm
                  .getJavaAlgorithmName());
    } else if (jwk instanceof JwkRsaPrivateKey) {
      JwkRsaPrivateKey rsaKey = (JwkRsaPrivateKey) jwk;
      return sign(payloadBytes, rsaKey.getPrivateKey(), algorithm.getJavaAlgorithmName());
    } else if (jwk instanceof JwkEcKey) {
      throw new UnsupportedOperationException("Elliptic curve keys are not supported");
    }
    return null;
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
}
