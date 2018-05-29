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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonMarshaller;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.StringTokenizer;

import static org.ietf.jose.util.Base64Utility.fromBase64Url;
import static org.ietf.jose.util.Base64Utility.fromBase64UrlToString;

/**
 * RFC 7515 JSON Web Signature (JWS)
 * <p>
 * 7.2.2. Flattened JWS JSON Serialization Syntax
 * <p>
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
 *  "payload":"_payload contents_",
 *  "protected":"_integrity-protected header contents_",
 *   "header":_non-integrity-protected header contents_,
 *   "signature":"_signature contents_"
 *  }</pre>
 * <p>
 * See Appendix A.7 for an example JWS using the flattened JWS JSON
 * Serialization syntax.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class FlattendedJsonSignature extends AbstractJws {

  /**
   * The "protected" member MUST be present and contain the value
   * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected Header value
   * is non-empty; otherwise, it MUST be absent. These Header Parameter values
   * are integrity protected.
   */
  @XmlElement(name = "protected")
  @Getter
  private JwsHeader protectedHeader;
  /**
   * The "header" member MUST be present and contain the value JWS Unprotected
   * Header when the JWS Unprotected Header value is non- empty; otherwise, it
   * MUST be absent. This value is represented as an unencoded JSON object,
   * rather than as a string. These Header Parameter values are not integrity
   * protected.
   */
  @XmlElement(name = "header")
  @Getter
  private JwsHeader unprotectedHeader;
  /**
   * The "signature" member MUST be present and contain the value BASE64URL(JWS
   * Signature).
   */
  @XmlElement(name = "signature")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] signature;

  /**
   * Default constructor; required for JSON/XML serializers
   */
  public FlattendedJsonSignature() {
  }

  public FlattendedJsonSignature(JwsHeader protectedHeader,
                                 JwsHeader unprotectedHeader,
                                 byte[] payload,
                                 byte[] signature) {
    this.protectedHeader = protectedHeader;
    this.unprotectedHeader = unprotectedHeader;
    this.payload = payload;
    this.signature = signature;
  }

  /**
   * Create instance from JSON string
   *
   * @param json JSON string
   * @return a FlattendedJsonSignature instance
   * @throws IOException in case of failure to deserialise the JSON string
   */
  public static FlattendedJsonSignature fromJson(String json) throws IOException {
    return JsonMarshaller.fromJson(json, FlattendedJsonSignature.class);
  }

  /**
   * Get the signature or HMAC bytes
   *
   * @return signature or HMAC bytes
   */
  public byte[] getSignatureBytes() {
    return signature;
  }

  /**
   * 3.1.  JWS Compact Serialization Overview
   * <p>
   * In the JWS Compact Serialization, no JWS Unprotected Header is used.
   * In this case, the JOSE Header and the JWS Protected Header are the
   * same.
   * <p>
   * In the JWS Compact Serialization, a JWS is represented as the
   * concatenation:
   * <pre>
   *       BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
   *       BASE64URL(JWS Payload) || ’.’ ||
   *       BASE64URL(JWS Signature)
   *       </pre>
   * See RFC 7515 Section 7.1 for more information about the JWS Compact
   * Serialization.
   *
   * @param text a valid compact JWS string
   * @return non-null JWE instance
   * @throws IOException
   * @throws IllegalArgumentException if the provided input is not a valid
   *                                  compact JWS string
   */
  public static FlattendedJsonSignature fromCompactForm(String text) throws IOException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 3) {
      throw new IllegalArgumentException("JWS compact form must have 3 elements separated by dots. Supplied string " +
          "has " + tokenizer.countTokens() + ".");
    }
    FlattendedJsonSignature jws = new FlattendedJsonSignature();
    String protectedHeaderJson = fromBase64UrlToString(tokenizer.nextToken());
    jws.protectedHeader = JsonMarshaller.fromJson(protectedHeaderJson, JwsHeader.class);
    jws.payload = fromBase64Url(tokenizer.nextToken());
    jws.signature = fromBase64Url(tokenizer.nextToken());
    return jws;
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
   */
  public String getCompactForm() throws IOException {
    return Base64Utility.toBase64Url(JsonMarshaller.toJson(protectedHeader))
        + '.' + Base64Utility.toBase64Url(payload)
        + '.' + Base64Utility.toBase64Url(signature);
  }

  /**
   * Validate signature
   *
   * @param base64UrlEncodedSecret base64Url-encoded bytes of the shared secret
   * @return true if the digital signature or HMAC is valid
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to validate the
   *                                  signature
   */
  public boolean isSignatureValid(String base64UrlEncodedSecret) throws IOException, GeneralSecurityException {
    return SignatureValidator.isValid(this, base64UrlEncodedSecret);
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
}
