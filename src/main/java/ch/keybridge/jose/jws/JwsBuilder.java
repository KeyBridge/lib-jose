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
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JwsBuilder {
  private byte[] payload;
  private List<JwsSignature> signatures = new ArrayList<>();

  private JwsBuilder() {
  }

  public static JwsBuilder getInstance() {
    return new JwsBuilder();
  }

  public JwsBuilder withBinaryPayload(byte[] payload) {
    this.payload = payload;
    return this;
  }

  public JwsBuilder withStringPayload(String payload) {
    this.payload = payload.getBytes(Base64Utility.DEFAULT_CHARSET);
    return this;
  }

  public JwsBuilder sign(JsonWebKey key) throws IOException, GeneralSecurityException {
    signatures.add(JwsSignature.getInstance(payload, key));
    return this;
  }

  public JwsBuilder sign(Key key, ESignatureAlgorithm algorithm) throws IOException, GeneralSecurityException {
    JoseCryptoHeader header = new JoseCryptoHeader();
    header.setAlg(algorithm.getJoseAlgorithmName());
    signatures.add(JwsSignature.getInstance(payload, key, header));
    return this;
  }

  public JwsBuilder sign(String secret, ESignatureAlgorithm algorithm) throws IOException, GeneralSecurityException {
    JoseCryptoHeader header = new JoseCryptoHeader();
    header.setAlg(algorithm.getJoseAlgorithmName());
    SecretKey key = new SecretKeySpec(secret.getBytes(Base64Utility.DEFAULT_CHARSET), algorithm.getJavaAlgorithmName());
    signatures.add(JwsSignature.getInstance(payload, key, header));
    return this;
  }

  public JwsJson buildJson() {
    return new JwsJson(payload, signatures);
  }

  public JwsJsonFlattened buildJsonFlattened() {
    return new JwsJson(payload, signatures).toFlattened();
  }

  public String buildCompact() throws IOException {
    return buildJsonFlattened().getCompactForm();
  }
}
