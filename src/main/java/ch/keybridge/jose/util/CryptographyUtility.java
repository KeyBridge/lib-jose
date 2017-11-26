package ch.keybridge.jose.util;

import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.jwk.JwkEcKey;
import ch.keybridge.jose.jwk.JwkRsaKey;
import ch.keybridge.jose.jwk.JwkSymmetricKey;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class CryptographyUtility {
  static {
//    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  public static byte[] encrypt(byte[] payload, Key key, String algo) throws GeneralSecurityException {
    return encrypt(payload, key, algo, null, null);
  }

  public static byte[] decrypt(byte[] payload, Key key, String algo) throws GeneralSecurityException {
    return decrypt(payload, key, algo, null, null);
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

  public static byte[] sign(byte[] payloadBytes, JWK key, ESignatureAlgorithm algorithm) throws GeneralSecurityException {
    String jcaAlgorithm = algorithm.getJavaAlgorithmName();
    if (key instanceof JwkSymmetricKey) {
      Mac mac = Mac.getInstance(jcaAlgorithm);
      JwkSymmetricKey symmetricKey = (JwkSymmetricKey)key;
      SecretKeySpec secret_key = new SecretKeySpec(symmetricKey.getK(), jcaAlgorithm);
      mac.init(secret_key);
      return mac.doFinal(payloadBytes);
    } else if (key instanceof JwkRsaKey) {
      Signature signer = Signature.getInstance(jcaAlgorithm);
      JwkRsaKey rsaKey = (JwkRsaKey) key;
      signer.initSign(rsaKey.getPrivateKey());
      signer.update(payloadBytes);
      return signer.sign();
    } else if (key instanceof JwkEcKey) {
      //todo
    }
    //todo process algorithm NONE
    return null;
  }
}
