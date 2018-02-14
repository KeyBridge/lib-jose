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

public class JwsBuilder {
  private byte[] payload;
  private List<JwsSignature> signatures = new ArrayList<>();

  public JwsBuilder withPayload(byte[] payload) {
    this.payload = payload;
    return this;
  }

  public JwsBuilder withPayload(String payload) {
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
    if (signatures.isEmpty()) throw new IllegalArgumentException("Must sign data!");
    JwsSignature signature = signatures.get(0);
    return new JwsJsonFlattened(signature.getProtectedHeader(), signature.getUnprotectedheader(), payload, signature
        .getSignature());
  }

  public String buildCompact() throws IOException {
    return buildJsonFlattened().getCompactForm();
  }
}
