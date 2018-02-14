package ch.keybridge.jose.util;

import ch.keybridge.jose.jwk.JsonWebKey;
import ch.keybridge.jose.jwk.JwkEcKey;
import ch.keybridge.jose.jwk.JwkRsaPrivateKey;
import ch.keybridge.jose.jwk.JwkSymmetricKey;
import ch.keybridge.jose.jws.ESignatureAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class CryptographyUtility {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static byte[] encrypt(byte[] payload, Key key, String algo) throws GeneralSecurityException {
    return encrypt(payload, key, algo, null, null);
  }

  public static byte[] decrypt(byte[] ciphertext, Key key, String algo) throws GeneralSecurityException {
    return decrypt(ciphertext, key, algo, null, null);
  }

  public static byte[] encrypt(byte[] payload, Key key, String algo, AlgorithmParameterSpec spec, byte[] additionalAUthenticationData) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    if (additionalAUthenticationData != null) {
      cipher.updateAAD(additionalAUthenticationData);
    }
    return cipher.doFinal(payload);
  }
  public static byte[] decrypt(byte[] ciphertext, Key key, String algo, AlgorithmParameterSpec spec, byte[] additionalAUthenticationData) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.DECRYPT_MODE, key, spec);
    if (additionalAUthenticationData != null) {
      cipher.updateAAD(additionalAUthenticationData);
    }
    return cipher.doFinal(ciphertext);
  }

  public static byte[] wrapKey(Key payloadKey, Key key, String algo) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.WRAP_MODE, key);
    return cipher.wrap(payloadKey);
  }

  public static Key unwrapKey(byte[] payload, Key key, String algo, String keyAlgo) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(Cipher.UNWRAP_MODE, key);
    return cipher.unwrap(payload, keyAlgo, Cipher.SECRET_KEY);
  }

  public static byte[] sign(byte[] payload, Key key, String alg) throws GeneralSecurityException {
    return key instanceof SecretKey ?
        sign(payload, (SecretKey) key, alg) :
        sign(payload, (PrivateKey) key, alg);
  }

  public static byte[] sign(byte[] payload, SecretKey key, String alg) throws GeneralSecurityException {
    Mac mac = Mac.getInstance(alg);
    mac.init(key);
    return mac.doFinal(payload);
  }

  public static boolean validate(byte[] signature, byte[] payload, SecretKey key, String algorithm) throws
      GeneralSecurityException {
    Mac mac = Mac.getInstance(algorithm);
    mac.init(key);
    byte[] computedMac = mac.doFinal(payload);
    return Arrays.equals(signature, computedMac);
  }

  public static byte[] sign(byte[] payload, PrivateKey key, String alg) throws GeneralSecurityException {
    Signature signer = Signature.getInstance(alg);
    signer.initSign(key);
    signer.update(payload);
    return signer.sign();
  }

  public static boolean validate(byte[] signature, byte[] payload, PublicKey key, String algorithm) throws
      GeneralSecurityException {
    Signature sig = Signature.getInstance(algorithm);
    sig.initVerify(key);
    sig.update(payload);
    return sig.verify(signature);
  }

  public static byte[] sign(byte[] payloadBytes, JsonWebKey jwk) throws GeneralSecurityException {
    ESignatureAlgorithm algorithm = ESignatureAlgorithm.resolveAlgorithm(jwk.getAlg());
    if (jwk instanceof JwkSymmetricKey) {
      JwkSymmetricKey symmetricKey = (JwkSymmetricKey) jwk;
      return sign(payloadBytes, new SecretKeySpec(symmetricKey.getK(), algorithm.getJavaAlgorithmName()), algorithm
          .getJavaAlgorithmName());
    } else if (jwk instanceof JwkRsaPrivateKey) {
      JwkRsaPrivateKey rsaKey = (JwkRsaPrivateKey) jwk;
      return sign(payloadBytes, rsaKey.getPrivateKey(), algorithm.getJavaAlgorithmName());
    } else if (jwk instanceof JwkEcKey) {
      //todo
    }
    //todo process algorithm NONE
    return null;
  }

  public static boolean validateSignature(byte[] signature, byte[] payload, Key key, String algorithm) throws
      GeneralSecurityException {
    if (key instanceof SecretKey) {
      return validate(signature, payload, (SecretKey) key, algorithm);
    } else if (key instanceof PublicKey) {
      return validate(signature, payload, (PublicKey) key, algorithm);
    }
    return false;
  }
}
