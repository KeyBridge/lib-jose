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
import lombok.ToString;
import org.ietf.jose.util.JsonMarshaller;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 7515 JSON Web Signature (GeneralJsonSignature)
 * <p>
 * JSON Web Signature (GeneralJsonSignature) represents content secured with
 * digital signatures or Message Authentication Codes (MACs) using JSON-based
 * data structures. Cryptographic algorithms and identifiers for use with this
 * specification are described in the separate JSON Web Algorithms (JWA)
 * specification and an IANA registry defined by that specification. Related
 * encryption capabilities are described in the separate JSON Web Encryption
 * (JWE) specification.
 * <p>
 * 7.2. GeneralJsonSignature JSON Serialization
 * <p>
 * The GeneralJsonSignature JSON Serialization represents digitally signed or
 * MACed content as a JSON object. This representation is neither optimized for
 * compactness nor URL-safe.
 * <p>
 * 7.2.1. General GeneralJsonSignature JSON Serialization Syntax
 * <p>
 * The following members are defined for use in top-level JSON objects used for
 * the fully general GeneralJsonSignature JSON Serialization syntax:
 * <p>
 * In summary, the syntax of a GeneralJsonSignature using the general
 * GeneralJsonSignature JSON Serialization is as follows:
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
 */
@XmlAccessorType(XmlAccessType.FIELD)
@EqualsAndHashCode(callSuper = true)
@ToString
public class GeneralJsonSignature extends AbstractJws {

  /**
   * The "signatures" member value MUST be an array of JSON objects. Each object
   * represents a signature or MAC over the GeneralJsonSignature Payload and the
   * GeneralJsonSignature Protected Header.
   */
  private List<Signature> signatures;

  /**
   * Default constructor. Used by JSON (de)serialisers.
   */
  private GeneralJsonSignature() {
  }

  public GeneralJsonSignature(byte[] payload, List<Signature> signatures) {
    this.payload = payload;
    this.signatures = signatures;
  }

  /**
   * Create instance from JSON string
   *
   * @param json JSON string
   * @return a FlattendedJsonSignature instace
   * @throws IOException in case of failure to deserialise the JSON string
   */
  public static GeneralJsonSignature fromJson(String json) throws IOException {
    return JsonMarshaller.fromJson(json, GeneralJsonSignature.class);
  }

  /**
   * Get the signatures as list
   *
   * @return signature list
   */
  public List<Signature> getSignatures() {
    return new ArrayList<>(signatures);
  }

  /**
   * Convert to FlattendedJsonSignature. Must contain a single signature.
   *
   * @return a FlattendedJsonSignature instance
   */
  public FlattendedJsonSignature toFlattened() {
    if (signatures.isEmpty()) {
      throw new IllegalArgumentException("Must sign data!");
    }
    if (signatures.size() > 1) {
      throw new IllegalArgumentException("JWS Flattened format support only one signature.");
    }
    Signature signature = signatures.get(0);
    return new FlattendedJsonSignature(
      signature.getProtectedHeader(), signature.getHeader(), payload, signature.getSignatureBytes());
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
