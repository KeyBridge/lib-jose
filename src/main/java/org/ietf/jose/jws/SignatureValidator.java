package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.ietf.jose.util.Base64Utility.toBase64Url;
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
   * Validate the HMAC of a FlattendedJsonSignature with the provided secret
   *
   * @param jws                    FlattendedJsonSignature instance
   * @param base64UrlEncodedSecret secret
   * @return true if the HMAC has been validated successfully
   * @throws IOException              in case of failure to serialize the JWS protected header to JSON
   */
  public static boolean isValid(FlattenedJsonSignature jws, String base64UrlEncodedSecret) throws IOException {
    String keyAlgorithm = jws.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName();
    SecretKey key = convertBase64UrlSecretToKey(keyAlgorithm, base64UrlEncodedSecret);
    return isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws.getSignatureBytes());
  }

  /**
   * Validate the digital signature of a FlattendedJsonSignature with the provided key
   *
   * @param jws FlattendedJsonSignature instance
   * @param key valid PublicKey
   * @return true if the HMAC has been validated successfully
   * @throws IOException              in case of failure to serialize the JWS protected header to JSON
   */
  public static boolean isValid(FlattenedJsonSignature jws, PublicKey key) throws IOException {
    return isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws.getSignatureBytes());
  }

  /**
   * Validate the digital signature of a FlattendedJsonSignature with the provided key
   *
   * @param jws    FlattendedJsonSignature instance
   * @param secret bytes of the shared secret used to create the HMAC
   * @return true if the HMAC has been validated successfully
   * @throws IOException              in case of failure to serialize the JWS protected header to JSON
   */
  public static boolean isValid(FlattenedJsonSignature jws, byte[] secret) throws IOException {
    String keyAlgorithm = jws.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName();
    SecretKey key = convertSecretToKey(keyAlgorithm, secret);
    return isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws.getSignatureBytes());
  }

  /**
   * Validate signature using a Key instance
   *
   * @param protectedHeader a JwsHeader instance
   * @param payload         data that was signed
   * @param key             a Key instance
   * @return true if signature is valid
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   */
  public static boolean isValid(AbstractHeader protectedHeader, byte[] payload, Key key, byte[] signature)
      throws IOException {
    String protectedHeaderJson = JsonMarshaller.toJson(protectedHeader);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    JwsAlgorithmType algorithm = protectedHeader.getJwsAlgorithmType();
    /**
     * The 'none' algorithm assumes an outside mechanism for validating integrity is in place
     * and in itself should be considered invalid.
     */
    if (algorithm == JwsAlgorithmType.NONE) return false;
    try {
      return CryptographyUtility.validateSignature(signature, fullPayload.getBytes(US_ASCII), key, algorithm
          .getJavaAlgorithmName());
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /**
   * Validate signature using a Key instance
   *
   * @param payload data that was signed
   * @param key     a Key instance
   * @return true if signature is valid
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   */
  public static boolean isValid(Signature signature, byte[] payload, PublicKey key) throws IOException {
    return isValid(signature.getProtectedHeader(), payload, key, signature.getSignatureBytes());
  }

  /**
   * Validate signature using shared secret
   *
   * @param payload                data that was signed
   * @param base64UrlEncodedSecret base64Url-encoded bytes of the shared secret
   * @return true if signature is valid
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   */
  public static boolean isValid(Signature signature, byte[] payload, String base64UrlEncodedSecret)
      throws IOException {
    String keyAlgorithm = signature.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName();
    Key key = convertBase64UrlSecretToKey(keyAlgorithm, base64UrlEncodedSecret);
    return isValid(signature.getProtectedHeader(), payload, key, signature.getSignatureBytes());
  }

  /**
   * Validate signature using shared secret
   *
   * @param payload data that was signed
   * @param secret  bytes of the shared secret used to create the HMAC
   * @return true if signature is valid
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   */
  public static boolean isValid(Signature signature, byte[] payload, byte[] secret)
      throws IOException {
    String keyAlgorithm = signature.getProtectedHeader().getJwsAlgorithmType().getJavaAlgorithmName();
    SecretKey key = convertSecretToKey(keyAlgorithm, secret);
    return isValid(signature.getProtectedHeader(), payload, key, signature.getSignatureBytes());
  }
}
