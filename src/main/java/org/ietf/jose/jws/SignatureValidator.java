package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwk.JsonWebKey;
import org.ietf.jose.util.CryptographyUtility;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;

import static org.ietf.jose.util.KeyUtility.convertBase64UrlSecretToKey;
import static org.ietf.jose.util.KeyUtility.convertSecretToKey;

/**
 * Validates digital signatures and HMACs.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class SignatureValidator {

  /**
   * Validate signature using a Key instance
   *
   * @param protectedHeader a JwsHeader instance
   * @param signingInput    the signing input
   * @param key             a Key instance
   * @return true if signature is valid
   */
  public static boolean isValid(AbstractHeader protectedHeader, byte[] signingInput, Key key, byte[] signature) {
    JwsAlgorithmType algorithm = protectedHeader.getJwsAlgorithmType();
    /**
     * The 'none' algorithm assumes an outside mechanism for validating integrity is in place
     * and in itself should be considered invalid.
     */
    if (algorithm == JwsAlgorithmType.NONE) return false;
    try {
      return CryptographyUtility.validateSignature(signature, signingInput, key, algorithm
          .getJavaAlgorithmName());
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /**
   * Validate signature using a Key instance
   *
   * @param signature a valid signature instance
   * @param key       a JSON Web Key instance
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, JsonWebKey key) {
    try {
      return CryptographyUtility.validateSignature(signature.getSignatureBytes(), signature.getSigningInput(),
          key, signature.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName());
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /**
   * Validate signature using a Key instance
   *
   * @param signature a valid signature instance
   * @param key     a Key instance
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, PublicKey key) {
    return isValid(signature.getProtectedHeader(), signature.getSigningInput(), key, signature.getSignatureBytes());
  }

  /**
   * Validate signature using a Key instance
   *
   * @param signature a valid signature instance
   * @param key       a Key instance
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, SecretKey key) {
    return isValid(signature.getProtectedHeader(), signature.getSigningInput(), key, signature.getSignatureBytes());
  }

  /**
   * Validate signature using shared secret
   *
   * @param signature              a valid signature instance
   * @param base64UrlEncodedSecret base64Url-encoded bytes of the shared secret
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, String base64UrlEncodedSecret) {
    String keyAlgorithm = signature.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName();
    Key key = convertBase64UrlSecretToKey(keyAlgorithm, base64UrlEncodedSecret);
    return isValid(signature.getProtectedHeader(), signature.getSigningInput(), key, signature.getSignatureBytes());
  }

  /**
   * Validate signature using shared secret
   *
   * @param signature a valid signature instance
   * @param secret    bytes of the shared secret used to create the HMAC
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, byte[] secret) {
    String keyAlgorithm = signature.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName();
    SecretKey key = convertSecretToKey(keyAlgorithm, secret);
    return isValid(signature.getProtectedHeader(), signature.getSigningInput(), key, signature.getSignatureBytes());
  }
}
