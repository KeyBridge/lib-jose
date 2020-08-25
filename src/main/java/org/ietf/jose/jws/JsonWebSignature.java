/*
 * Copyright 2018 Key Bridge.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ietf.jose.jws;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTransient;
import javax.json.bind.annotation.JsonbTypeAdapter;
import org.ietf.jose.adapter.JsonJwsHeaderAdapter;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbUtility;

import static org.ietf.jose.util.Base64Utility.fromBase64Url;
import static org.ietf.jose.util.Base64Utility.fromBase64UrlToString;

/**
 * <h1>RFC 7515 JSON Web Signature (JWS)</h1>
 * <p>
 * JSON Web Signature (JWS) represents content secured with digital signatures
 * or Message Authentication Codes (MACs) using JSON-based data structures.
 * Cryptographic algorithms and identifiers for use with this specification are
 * described in the separate JSON Web Algorithms (JWA) specification and an IANA
 * registry defined by that specification. Related encryption capabilities are
 * described in the separate JSON Web Encryption (JWE) specification.
 * <h2>7.2. JWS JSON Serialization</h2>
 * The JWS JSON Serialization represents digitally signed or MACed content as a
 * JSON object. This representation is neither optimized for compactness nor
 * URL-safe.
 * <h3>7.2.1. General JWS JSON Serialization Syntax</h3>
 * The following members are defined for use in top-level JSON objects used for
 * the fully general JWS JSON Serialization syntax:
 * <p>
 * In summary, the syntax of a JWS using the general JWS JSON Serialization is
 * as follows:
 * <pre>
 * {
 *  "payload":"_payload contents_",
 *  "signatures":[
 *   {"protected":"_integrity-protected header 1 contents_",
 *    "header":_non-integrity-protected header 1 contents_,
 *    "signature":"_signature 1 contents_"},
 *    ...
 *   {"protected":"_integrity-protected header N contents_",
 *    "header":_non-integrity-protected header N contents_,
 *    "signature":"_signature N contents_"}]
 * }</pre>
 * <h3>7.2.2. Flattened JWS JSON Serialization Syntax</h3>
 * The flattened JWS JSON Serialization syntax is based upon the general syntax
 * but flattens it, optimizing it for the single digital signature/MAC case. It
 * flattens it by removing the "signatures" member and instead placing those
 * members defined for use in the "signatures" array (the "protected", "header",
 * and "signature" members) in the top-level JSON object (at the same level as
 * the "payload" member).
 * <p>
 * The "signatures" member MUST NOT be present when using this syntax. Other
 * than this syntax difference, JWS JSON Serialization objects using the
 * flattened syntax are processed identically to those using the general syntax.
 * <p>
 * In summary, the syntax of a JWS using the flattened JWS JSON Serialization is
 * as follows:
 * <pre>
 * {
 *   "payload":"[payload contents]",
 *   "protected":"[integrity-protected header contents]",
 *   "header":[non-integrity-protected header contents],
 *   "signature":"[signature contents]"
 * }</pre>
 */
public class JsonWebSignature extends JsonSerializable {

  /**
   * The "payload" member MUST be present and contain the value BASE64URL(JWS
   * Payload).
   */
  private byte[] payload;
  /**
   * The "protected" member MUST be present and contain the value
   * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected Header value
   * is non-empty; otherwise, it MUST be absent. These Header Parameter values
   * are integrity protected.
   */
  @JsonbProperty("protected")
  @JsonbTypeAdapter(JsonJwsHeaderAdapter.class)
  private JwsHeader protectedHeader;
  /**
   * The "header" member MUST be present and contain the value JWS Unprotected
   * Header when the JWS Unprotected Header value is non- empty; otherwise, it
   * MUST be absent. This value is represented as an unencoded JSON object,
   * rather than as a string. These Header Parameter values are not integrity
   * protected.
   */
  @JsonbProperty("header")
  private JwsHeader unprotectedHeader;
  /**
   * The "signature" member MUST be present and contain the value BASE64URL(JWS
   * Signature).
   */
  @JsonbProperty("signature")
  private byte[] signature;

  /**
   * JWS Signing Input
   * <pre>
   *        ASCII(BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
   *        BASE64URL(JWS Payload))
   * </pre>
   */
  @JsonbTransient
  private byte[] jwsSigningInput;

  /**
   * The "signatures" member value MUST be an array of JSON objects. Each object
   * represents a signature or MAC over the GeneralJsonSignature Payload and the
   * GeneralJsonSignature Protected Header.
   */
  @JsonbProperty("signatures")
  private List<Signature> signatures;

  /**
   * Default no-arg constructor. Used by JSON (de)serialisers.
   */
  public JsonWebSignature() {
  }

  public JsonWebSignature(byte[] payload, List<Signature> signatures) {
    this.payload = payload;
    if (signatures.isEmpty()) {
      throw new IllegalArgumentException("A JWS object must have at least one signature");
    } else if (signatures.size() == 1) {
      Signature sig = signatures.get(0);
      this.signature = sig.getSignatureBytes();
      this.protectedHeader = sig.getProtectedHeader();
      this.unprotectedHeader = sig.getHeader();
      this.jwsSigningInput = sig.getSigningInput();
    } else {
      this.signatures = signatures;
    }
  }

  /**
   * Create instance from JSON string
   *
   * @param json JSON string
   * @return a FlattenedJsonSignature instance
   * @throws IOException in case of failure to deserialize the JSON string
   */
  public static JsonWebSignature fromJson(String json) throws IOException {
    JsonWebSignature jws = new JsonbUtility().unmarshal(json, JsonWebSignature.class);
    /**
     * Read the JSON again but with retained protected header order. This is
     * necessary later when verifying the digital signature on HMAC.
     */
    JwsFrame frame = new JsonbUtility().unmarshal(json, JwsFrame.class);

    if (jws.protectedHeader != null) {
      // this is a single-signature JWS (flattened)
      jws.jwsSigningInput = createSignatureInput(frame);
    } else if (!jws.signatures.isEmpty()) {
      // this is a general JWS JSON object
      for (int i = 0; i < jws.signatures.size(); i++) {
        jws.signatures.get(i).setJwsSigningInput(createSignatureInput(frame.signatures.get(i)));
      }
    } else {
      throw new IllegalArgumentException("Invalid JWS JSON input");
    }
    return jws;
  }

  private static byte[] createSignatureInput(JwsFrame frame) {
    String signingInputString = frame.protectedHeaderJsonBase64Url + '.' + frame.payload;
    return signingInputString.getBytes(StandardCharsets.US_ASCII);
  }

  /**
   * 3.1. JWS Compact Serialization Overview
   * <p>
   * In the JWS Compact Serialization, no JWS Unprotected Header is used. In
   * this case, the JOSE Header and the JWS Protected Header are the same.
   * <p>
   * In the JWS Compact Serialization, a JWS is represented as the
   * concatenation:
   * <pre>
   *       BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
   *       BASE64URL(JWS Payload) || ’.’ ||
   *       BASE64URL(JWS Signature)
   * </pre> See RFC 7515 Section 7.1 for more information about the JWS Compact
   * Serialization.
   *
   * @param text a valid compact JWS string
   * @return non-null JWE instance
   * @throws IOException              on serialization error
   * @throws IllegalArgumentException if the provided input is not a valid
   *                                  compact JWS string
   */
  public static JsonWebSignature fromCompactForm(String text) throws IOException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 3) {
      throw new IllegalArgumentException("JWS compact form must have 3 elements separated by dots. Supplied string "
        + "has " + tokenizer.countTokens() + ".");
    }
    JsonWebSignature jws = new JsonWebSignature();
    String protectedHeaderBase64Url = tokenizer.nextToken();
    String payloadBase64Url = tokenizer.nextToken();
    String signatureBase64Url = tokenizer.nextToken();

    String protectedHeaderJson = fromBase64UrlToString(protectedHeaderBase64Url);
    jws.protectedHeader = new JsonbUtility().unmarshal(protectedHeaderJson, JwsHeader.class);
    jws.payload = fromBase64Url(payloadBase64Url);
    jws.signature = fromBase64Url(signatureBase64Url);

    jws.jwsSigningInput = (protectedHeaderBase64Url + '.' + payloadBase64Url).getBytes(StandardCharsets.US_ASCII);
    return jws;
  }

  /**
   * Get the JWS payload as string.
   *
   * @return string payload
   */
  public String getStringPayload() {
    return new String(payload, Base64Utility.DEFAULT_CHARSET);
  }

  /**
   * Get the signatures as list
   *
   * @return signature list
   */
  public List<Signature> getSignatures() {
    if (protectedHeader != null) {
      return Collections.singletonList(getSignature());
    }
    return new ArrayList<>(signatures);
  }

  /**
   * Get the first signature. In most cases a JWS will have only one signature.
   *
   * @return first signature
   */
  public Signature getSignature() {
    return Signature.getInstance(jwsSigningInput, signature, protectedHeader, unprotectedHeader);
  }

  /**
   * 7.1. JWS Compact Serialization
   * <p>
   * The JWS Compact Serialization represents digitally signed or MACed content
   * as a compact, URL-safe string. This string is:
   * <pre>
   * BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
   * BASE64URL(JWS Payload) || ’.’ ||
   * BASE64URL(JWS Signature)
   * </pre> Only one signature/MAC is supported by the JWS Compact Serialization
   * and it provides no syntax to represent a JWS Unprotected Header value.
   *
   * @return this JWS object encoded in compact serialization
   * @throws java.io.IOException on Error encountered while serializing
   */
  public String toCompactForm() throws IOException {
    JwsHeader compactProtectedHeader;
    byte[] compactSignature;
    if (this.protectedHeader != null) {
      compactProtectedHeader = this.protectedHeader;
      compactSignature = this.signature;
    } else if (!signatures.isEmpty()) {
      Signature firstSignature = signatures.get(0);
      compactProtectedHeader = firstSignature.getProtectedHeader();
      compactSignature = firstSignature.getSignatureBytes();
    } else {
      throw new IllegalStateException("JWS is empty");
    }
    return Base64Utility.toBase64Url(new JsonbUtility().marshal(compactProtectedHeader))
      + '.' + Base64Utility.toBase64Url(payload)
      + '.' + Base64Utility.toBase64Url(compactSignature);
  }

  /**
   * A loosely-typed JWS representation that retains order of elements as in the
   * original JSON string.
   */
  public static final class JwsFrame {

    private String payload;
    @JsonbProperty("protected")
    private String protectedHeaderJsonBase64Url;
    private Map<String, String> header;
    private String signature;
    private List<JwsFrame> signatures;

    //<editor-fold defaultstate="collapsed" desc="Getter and Setter">
    public String getPayload() {
      return payload;
    }

    public void setPayload(String payload) {
      this.payload = payload;
    }

    public String getProtectedHeaderJsonBase64Url() {
      return protectedHeaderJsonBase64Url;
    }

    public void setProtectedHeaderJsonBase64Url(String protectedHeaderJsonBase64Url) {
      this.protectedHeaderJsonBase64Url = protectedHeaderJsonBase64Url;
    }

    public Map<String, String> getHeader() {
      return header;
    }

    public void setHeader(Map<String, String> header) {
      this.header = header;
    }

    public String getSignature() {
      return signature;
    }

    public void setSignature(String signature) {
      this.signature = signature;
    }

    public List<JwsFrame> getSignatures() {
      return signatures;
    }

    public void setSignatures(List<JwsFrame> signatures) {
      this.signatures = signatures;
    }//</editor-fold>

  }

}
