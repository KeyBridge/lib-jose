package org.ietf.jose.jws;

import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.ietf.jose.util.Base64Utility.toBase64Url;

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
   * @throws GeneralSecurityException in case signature algorithms are not available
   *                                  or another security-related issue
   */
  public static boolean isValid(FlattenedJsonSignature jws, String base64UrlEncodedSecret) throws IOException,
      GeneralSecurityException {
    SecretKey key = convertBase64UrlSecretToKey(jws.getProtectedHeader().getJwsAlgorithmType(), base64UrlEncodedSecret);
    return isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws.getSignatureBytes());
  }

  /**
   * Validate the digital signature of a FlattendedJsonSignature with the provided key
   *
   * @param jws FlattendedJsonSignature instance
   * @param key valid PublicKey
   * @return true if the HMAC has been validated successfully
   * @throws IOException              in case of failure to serialize the JWS protected header to JSON
   * @throws GeneralSecurityException in case signature algorithms are not available
   *                                  or another security-related issue
   */
  public static boolean isValid(FlattenedJsonSignature jws, PublicKey key) throws IOException,
      GeneralSecurityException {
    return isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws.getSignatureBytes());

  }

  /**
   * Validate the digital signature of a FlattendedJsonSignature with the provided key
   *
   * @param jws    FlattendedJsonSignature instance
   * @param secret bytes of the shared secret used to create the HMAC
   * @return true if the HMAC has been validated successfully
   * @throws IOException              in case of failure to serialize the JWS protected header to JSON
   * @throws GeneralSecurityException in case signature algorithms are not available
   *                                  or another security-related issue
   */
  public static boolean isValid(FlattenedJsonSignature jws, byte[] secret) throws IOException,
      GeneralSecurityException {
    SecretKey key = convertSecretToKey(jws.getProtectedHeader().getJwsAlgorithmType(), secret);
    return isValid(jws.getProtectedHeader(), jws.getPayload(), key, jws.getSignatureBytes());
  }

  /**
   * Convert a base64URL-encoded secret into a Key
   *
   * @param algorithm              secret key algorithm
   * @param base64UrlEncodedSecret base64UrlEncodedSecret
   * @return a SecretKey instance
   */
  private static SecretKey convertBase64UrlSecretToKey(JwsAlgorithmType algorithm, String base64UrlEncodedSecret) {
    byte[] secret = Base64Utility.fromBase64Url(base64UrlEncodedSecret);
    return new SecretKeySpec(secret, algorithm.getJavaAlgorithmName());
  }

  /**
   * Convert a base64URL-encoded secret into a Key
   *
   * @param algorithm secret key algorithm
   * @param secret    bytes of the secret used to create the HMAC
   * @return a SecretKey instance
   */
  private static SecretKey convertSecretToKey(JwsAlgorithmType algorithm, byte[] secret) {
    return new SecretKeySpec(secret, algorithm.getJavaAlgorithmName());
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
   * @throws GeneralSecurityException in case of failure to validate the
   *                                  signature
   */
  public static boolean isValid(AbstractHeader protectedHeader, byte[] payload, Key key, byte[] signature)
      throws IOException, GeneralSecurityException {
    String protectedHeaderJson = JsonMarshaller.toJson(protectedHeader);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    JwsAlgorithmType algorithm = protectedHeader.getJwsAlgorithmType();
    return CryptographyUtility.validateSignature(signature, fullPayload.getBytes(US_ASCII), key, algorithm
        .getJavaAlgorithmName());
  }

  /**
   * Validate signature using a Key instance
   *
   * @param payload data that was signed
   * @param key     a Key instance
   * @return true if signature is valid
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to validate the
   *                                  signature
   */
  public static boolean isValid(Signature signature, byte[] payload, PublicKey key) throws IOException,
      GeneralSecurityException {
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
   * @throws GeneralSecurityException in case of failure to validate the
   *                                  signature
   */
  public static boolean isValid(Signature signature, byte[] payload, String base64UrlEncodedSecret)
      throws IOException, GeneralSecurityException {
    JwsAlgorithmType algorithm = signature.getProtectedHeader().getJwsAlgorithmType();
    Key key = convertBase64UrlSecretToKey(algorithm, base64UrlEncodedSecret);
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
   * @throws GeneralSecurityException in case of failure to validate the
   *                                  signature
   */
  public static boolean isValid(Signature signature, byte[] payload, byte[] secret)
      throws IOException, GeneralSecurityException {
    JwsAlgorithmType algorithm = signature.getProtectedHeader().getJwsAlgorithmType();
    SecretKey key = convertSecretToKey(algorithm, secret);
    return isValid(signature.getProtectedHeader(), payload, key, signature.getSignatureBytes());
  }
}
