package ch.keybridge.jose.jws;

import ch.keybridge.jose.util.Base64Utility;
import ch.keybridge.jose.util.JsonMarshaller;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

/**
 * JSON Web Signature (JWS) represents content secured with digital signatures
 * or Message Authentication Codes (MACs) using JSON-based data structures.
 * Cryptographic algorithms and identifiers for use with this specification are
 * described in the separate JSON Web Algorithms (JWA) specification and an IANA
 * registry defined by that specification. Related encryption capabilities are
 * described in the separate JSON Web Encryption (JWE) specification.
 * <p>
 * 7.2.1. General JWS JSON Serialization Syntax The following members are
 * defined for use in top-level JSON objects used for the fully general JWS JSON
 * Serialization syntax:
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwsJson extends JwsJsonBase {
//  private static final Logger LOG = Logger.getLogger(JwsJson.class.getCanonicalName());

  /**
   * The "signatures" member value MUST be an array of JSON objects. Each object
   * represents a signature or MAC over the JWS Payload and the JWS Protected
   * Header.
   */
  private List<JwsSignature> signatures;

  public JwsJson() {
  }

  public JwsJson(byte[] payload, List<JwsSignature> signatures) {
    this.payload = payload;
    this.signatures = signatures;
  }

  public static JwsJson fromJson(String json) throws IOException {
    return JsonMarshaller.fromJson(json, JwsJson.class);
  }

  public List<JwsSignature> getSignatures() {
    return new ArrayList<>(signatures);
  }

  public JwsJsonFlattened toFlattened() {
    if (signatures.isEmpty()) {
      throw new IllegalArgumentException("Must sign data!");
    }
    if (signatures.size() > 1) {
      throw new IllegalArgumentException("JWS Flattened format support only one signature.");
    }
    JwsSignature signature = signatures.get(0);
    return new JwsJsonFlattened(
      signature.getProtectedHeader(), signature.getUnprotectedheader(), payload, signature.getSignatureBytes());
  }

  public String toJson() throws IOException {
    return JsonMarshaller.toJson(this);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    JwsJson jwsJson = (JwsJson) o;

    if (payload != null ? !Arrays.equals(payload, jwsJson.payload) : jwsJson.payload != null) {
      return false;
    }
    return signatures != null ? signatures.equals(jwsJson.signatures) : jwsJson.signatures == null;
  }

  @Override
  public int hashCode() {
    int result = payload != null ? Arrays.hashCode(payload) : 0;
    result = 31 * result + (signatures != null ? signatures.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "JWSJson{"
      + "payload='" + Base64Utility.toBase64Url(payload) + '\''
      + ", signatures=" + signatures
      + '}';
  }
}
