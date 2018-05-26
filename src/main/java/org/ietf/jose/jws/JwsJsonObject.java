package org.ietf.jose.jws;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonMarshaller;

/**
 * RFC 7515 JSON Web Signature (JWS)
 * <p>
 * JSON Web Signature (JWS) represents content secured with digital signatures
 * or Message Authentication Codes (MACs) using JSON-based data structures.
 * Cryptographic algorithms and identifiers for use with this specification are
 * described in the separate JSON Web Algorithms (JWA) specification and an IANA
 * registry defined by that specification. Related encryption capabilities are
 * described in the separate JSON Web Encryption (JWE) specification.
 * <p>
 * 7.2. JWS JSON Serialization
 * <p>
 * The JWS JSON Serialization represents digitally signed or MACed content as a
 * JSON object. This representation is neither optimized for compactness nor
 * URL-safe.
 * <p>
 * 7.2.1. General JWS JSON Serialization Syntax
 * <p>
 * The following members are defined for use in top-level JSON objects used for
 * the fully general JWS JSON Serialization syntax:
 * <p>
 * 7.2.1. General JWS JSON Serialization Syntax The following members are
 * defined for use in top-level JSON objects used for the fully general JWS JSON
 * Serialization syntax:
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwsJsonObject extends JwsJsonBase {

  /**
   * The "signatures" member value MUST be an array of JSON objects. Each object
   * represents a signature or MAC over the JWS Payload and the JWS Protected
   * Header.
   */
  private List<JwsJsonSignature> signatures;

  /**
   * Default constructor. Used by JSON (de)serialisers.
   */
  private JwsJsonObject() {
  }

  public JwsJsonObject(byte[] payload, List<JwsJsonSignature> signatures) {
    this.payload = payload;
    this.signatures = signatures;
  }

  /**
   * Create instance from JSON string
   *
   * @param json JSON string
   * @return a JwsJsonFlattened instace
   * @throws IOException in case of failure to deserialise the JSON string
   */
  public static JwsJsonObject fromJson(String json) throws IOException {
    return JsonMarshaller.fromJson(json, JwsJsonObject.class);
  }

  /**
   * Get the signatures as list
   *
   * @return signature list
   */
  public List<JwsJsonSignature> getSignatures() {
    return new ArrayList<>(signatures);
  }

  /**
   * Convert to JwsJsonFlattened. Must contain a single signature.
   *
   * @return a JwsJsonFlattened instance
   */
  public JwsJsonFlattened toFlattened() {
    if (signatures.isEmpty()) {
      throw new IllegalArgumentException("Must sign data!");
    }
    if (signatures.size() > 1) {
      throw new IllegalArgumentException("JWS Flattened format support only one signature.");
    }
    JwsJsonSignature signature = signatures.get(0);
    return new JwsJsonFlattened(
      signature.getProtectedHeader(), signature.getUnprotectedHeader(), payload, signature.getSignatureBytes());
  }

  /**
   * Serialise to JSON.
   *
   * @return JSON string
   * @throws IOException in case of failure to serialise the object to JSON
   */
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

    JwsJsonObject jwsJson = (JwsJsonObject) o;

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
