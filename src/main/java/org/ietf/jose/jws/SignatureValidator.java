package org.ietf.jose.jws;

import ch.keybridge.lib.jose.AbstractHeader;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.jwk.key.AbstractJwk;
import org.ietf.jose.util.CryptographyUtility;

import static org.ietf.jose.util.KeyUtility.convertSecretToKey;

/**
 * Validates digital signatures and HMACs.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class SignatureValidator {

  /**
   * Validate signature using a {@code java.security.Key} instance
   *
   * @param protectedHeader a JwsHeader instance
   * @param signingInput    the signing input
   * @param key             a {@code java.security.Key} instance
   * @param signature       the signature bytes
   * @return true if signature is valid
   */
  public static boolean isValid(AbstractHeader protectedHeader, byte[] signingInput, Key key, byte[] signature) {
    JwsAlgorithmType algorithm = protectedHeader.getJwsAlgorithmType();
    /**
     * The 'none' algorithm assumes an outside mechanism for validating
     * integrity is in place and in itself should be considered invalid.
     */
    if (algorithm == JwsAlgorithmType.NONE) {
      return false;
    }
    try {
      return CryptographyUtility.validateSignature(signature,
                                                   signingInput,
                                                   key,
                                                   algorithm.getJavaAlgorithmName());
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /**
   * Validate signature using a JsonWebKey instance
   *
   * @param signature a valid signature instance
   * @param key       a JSON Web Key instance
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, AbstractJwk key) {
    try {
      return CryptographyUtility.validateSignature(signature.getSignatureBytes(),
                                                   signature.getSigningInput(),
                                                   key,
                                                   signature.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName());
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /**
   * Validate signature using a Key instance
   *
   * @param signature a valid signature instance
   * @param key       a Key instance
   * @return true if signature is valid
   */
  public static boolean isValid(Signature signature, Key key) {
    return isValid(signature.getProtectedHeader(), signature.getSigningInput(), key, signature.getSignatureBytes());
  }

  /**
   * Require that at least one signature in the provided list is valid.
   *
   * @param jws a JSON web signature.
   * @param key the key to match against
   * @return TRUE if any one of the signatures is valid
   */
  public static boolean isValid(JsonWebSignature jws, Key key) {
    return jws.getSignatures().stream().anyMatch(s -> isValid(s, key));
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

  /**
   * Validate signature using shared secret
   *
   * @param signature    a valid signature instance
   * @param sharedSecret a string shared secret. Can be any arbitrary string.
   * @return true if signature is valid
   * @throws java.security.NoSuchAlgorithmException if the secret key algorithm
   *                                                is not supported
   */
  public static boolean isValid(Signature signature, String sharedSecret) throws NoSuchAlgorithmException {
    SecretKey key = SecretKeyBuilder.fromSharedSecret(sharedSecret);
    return isValid(signature, key);
  }

}
