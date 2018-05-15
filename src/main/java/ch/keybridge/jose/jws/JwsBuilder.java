package ch.keybridge.jose.jws;

import ch.keybridge.jose.JoseCryptoHeader;
import ch.keybridge.jose.jwk.JsonWebKey;
import ch.keybridge.jose.util.Base64Utility;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

/**
 * A builder for JSON Web Signature objects.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JwsBuilder {
  private byte[] payload;
  private List<JwsSignature> signatures = new ArrayList<>();
  private JoseCryptoHeader protectedHeader;
  private JoseCryptoHeader unprotectedHeader;

  private JwsBuilder() {
  }

  /**
   * Create new instance of the builder
   *
   * @return a new builder instance
   */
  public static JwsBuilder getInstance() {
    return new JwsBuilder();
  }

  /**
   * Add binary payload for signing or HMAC calculation
   *
   * @param payload data to sign
   * @return this builder
   */
  public JwsBuilder withBinaryPayload(byte[] payload) {
    this.payload = payload;
    return this;
  }

  /**
   * Add string payload for signing or HMAC calculation
   * @param payload string to sign
   * @return this builder
   */
  public JwsBuilder withStringPayload(String payload) {
    this.payload = payload.getBytes(Base64Utility.DEFAULT_CHARSET);
    return this;
  }

  /**
   * Add a protected header
   * @param header a JoseCryptoHeader instance
   * @return this builder
   */
  public JwsBuilder withProtectedHeader(JoseCryptoHeader header) {
    protectedHeader = header;
    return this;
  }

  /**
   * Add an unprotected header
   * @param header a JoseCryptoHeader instance
   * @return this builder
   */
  public JwsBuilder withUnprotectedHeader(JoseCryptoHeader header) {
    unprotectedHeader = header;
    return this;
  }

  /**
   * Sign using a JsonWebKey
   * @param key a JsonWebKey instance
   * @return this builder
   * @throws IOException in case of failure to serialise the protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(JsonWebKey key) throws IOException, GeneralSecurityException {
    signatures.add(JwsSignature.getInstance(payload, key));
    return this;
  }

  /**
   * Sign using a Key instance and specific algorithm
   * @param key Key instance
   * @param algorithm a signature algorithm suitable for the provided key
   * @return this builder
   * @throws IOException in case of failure to serialise the protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(Key key, ESignatureAlgorithm algorithm) throws IOException, GeneralSecurityException {
    if (protectedHeader == null) protectedHeader = new JoseCryptoHeader();
    protectedHeader.setAlg(algorithm.getJoseAlgorithmName());
    signatures.add(JwsSignature.getInstance(payload, key, protectedHeader, unprotectedHeader));
    return this;
  }

  /**
   * Sign with a keyed hash (HMAC)
   * @param secret a base64URL-encoded secret
   * @param algorithm a signature algorithm suitable for the provided key
   * @return this builder
   * @throws IOException in case of failure to serialise the protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(String secret, ESignatureAlgorithm algorithm) throws IOException, GeneralSecurityException {
    SecretKey key = new SecretKeySpec(Base64Utility.fromBase64Url(secret), algorithm.getJavaAlgorithmName());
    return sign(key, algorithm);
  }

  /**
   * Sign with a keyed hash (HMAC)
   * @param secret a base64URL-encoded secret
   * @return this builder
   * @throws IOException in case of failure to serialise the protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public JwsBuilder sign(String secret) throws IOException, GeneralSecurityException {
    byte[] keyBytes = Base64Utility.fromBase64Url(secret);
    ESignatureAlgorithm algorithm;
    switch (keyBytes.length) {
      case 32:
        algorithm = ESignatureAlgorithm.HS256;
        break;
      case 48:
        algorithm = ESignatureAlgorithm.HS384;
        break;
      case 64:
        algorithm = ESignatureAlgorithm.HS512;
        break;
      default:
        throw new IllegalArgumentException("Unsupported key length: " + keyBytes.length);
    }
    SecretKey key = new SecretKeySpec(keyBytes, algorithm.getJavaAlgorithmName());
    return sign(key, algorithm);
  }

  /**
   * Build a JwsJson instance: A JWS object with one or more signatures
   * @return a JwsJson instance
   */
  public JwsJson buildJson() {
    return new JwsJson(payload, signatures);
  }

  /**
   * Build a JwsJsonFlattened instance: A JWS object with a single signature.
   * @return a JwsJsonFlattened instance
   */
  public JwsJsonFlattened buildJsonFlattened() {
    return new JwsJson(payload, signatures).toFlattened();
  }

  /**
   * Build a JWS compact string: a string which contains the payload and a single signature.
   * @return a JWS compact string
   */
  public String buildCompact() throws IOException {
    return buildJsonFlattened().getCompactForm();
  }
}
