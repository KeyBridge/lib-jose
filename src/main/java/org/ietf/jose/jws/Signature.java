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

import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwk.JWK;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.ietf.jose.util.Base64Utility.toBase64Url;

/**
 * RFC 7515 JSON Web Signature (JWS)
 * <p>
 * 7.2.1. General JWS JSON Serialization Syntax
 * <p>
 * The following members are defined for use in the JSON objects that are
 * elements of the "signatures" array:
 * <p>
 * protected: The "protected" member MUST be present and contain the value
 * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected Header value is
 * non-empty; otherwise, it MUST be absent. These Header Parameter values are
 * integrity protected.
 * <p>
 * header: The "header" member MUST be present and contain the value JWS
 * Unprotected Header when the JWS Unprotected Header value is non- empty;
 * otherwise, it MUST be absent. This value is represented as an unencoded JSON
 * object, rather than as a string. These Header Parameter values are not
 * integrity protected.
 * <p>
 * signature: The "signature" member MUST be present and contain the value
 * BASE64URL(JWS Signature).
 * <p>
 * In summary, the syntax of a JWS using the flattened JWS JSON Serialization is
 * as follows:
 * <pre>
 * {
 *  "payload":"_payload contents_",
 *  "protected":"_integrity-protected header contents_",
 *  "header":_non-integrity-protected header contents_,
 *  "signature":"_signature contents_"
 * }</pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class Signature {

  /**
   * The "protected" member MUST be present and contain the value
   * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected Header value
   * is non-empty; otherwise, it MUST be absent. These Header Parameter values
   * are integrity protected.
   */
  @XmlElement(name = "protected")
  private JwsHeader protectedHeader;
  /**
   * The "header" member MUST be present and contain the value JWS Unprotected
   * Header when the JWS Unprotected Header value is non- empty; otherwise, it
   * MUST be absent. This value is represented as an unencoded JSON object,
   * rather than as a string. These Header Parameter values are not integrity
   * protected.
   */
  @XmlElement(name = "header")
  private JwsHeader header;
  /**
   * The "signature" member MUST be present and contain the value BASE64URL(JWS
   * Signature).
   */
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] signature;

  /**
   * Create signature for the provided payload and JSON Web Key
   *
   * @param payload data to sign
   * @param key     a valid JWK instance
   * @return a JWS instance
   * @throws IOException              in case of failure to serialise the
   *                                  protected header to JSON
   * @throws GeneralSecurityException in case of failure to sign
   */
  public static Signature getInstance(byte[] payload, JWK key) throws IOException, GeneralSecurityException {
    Signature signature = new Signature();
    JwsHeader ph = new JwsHeader();
    ph.setAlg(key.getAlg());
    ph.setX5c(key.getX5c());
    ph.setX5t(key.getX5t());
    ph.setX5tS256(key.getX5tS256());
    ph.setX5u(key.getX5u());
    ph.setKid(key.getKid());
    signature.protectedHeader = ph;
    validateProtectedHeader(ph);

    String protectedHeaderJson = JsonMarshaller.toJson(ph);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    signature.signature = CryptographyUtility.sign(fullPayload.getBytes(US_ASCII), key);
    return signature;
  }

  /**
   * Create signature for the provided payload, key, and protected header
   *
   * @param payload         data to sign
   * @param key             a valid key. Must be an instance of
   *                        javax.crypto.SecretKey or java.security.PrivateKey
   * @param protectedHeader a JwsHeader that will be integrity-protected by the
   *                        signature
   * @return JWS instance
   * @throws IOException
   * @throws GeneralSecurityException
   */
  public static Signature getInstance(byte[] payload, Key key, JwsHeader protectedHeader) throws IOException,
      GeneralSecurityException {
    return getInstance(payload, key, protectedHeader, null);
  }

  /**
   * Create signature for the provided payload, key, and headers
   *
   * @param payload           data to sign
   * @param key               a valid key. Must be an instance of
   *                          javax.crypto.SecretKey or java.security.PrivateKey
   * @param protectedHeader   a JwsHeader that will be integrity-protected
   * @param unprotectedHeader a JwsHeader that will not be integrity-protected
   *                          by the signature
   * @return JWS instance
   * @throws IOException
   * @throws GeneralSecurityException
   */
  public static Signature getInstance(byte[] payload, Key key, JwsHeader protectedHeader, JwsHeader
      unprotectedHeader) throws IOException, GeneralSecurityException {
    validateProtectedHeader(protectedHeader);
    Signature signature = new Signature();
    signature.protectedHeader = protectedHeader;
    signature.header = unprotectedHeader;
    JwsAlgorithmType algorithm = protectedHeader.getJwsAlgorithmType();

    String protectedHeaderJson = JsonMarshaller.toJson(signature.protectedHeader);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    signature.signature = CryptographyUtility.sign(fullPayload.getBytes(US_ASCII), key, algorithm
        .getJavaAlgorithmName());
    return signature;
  }

  /**
   * Checks if the 'kid' field is set. Other checks can be added in future versions of the library.
   *
   * @param protectedHeader non-null protected header
   */
  private static void validateProtectedHeader(JwsHeader protectedHeader) {
    if (protectedHeader.getKid() == null) {
      throw new IllegalArgumentException("The protected header must have a key ID ('kid' field) populated");
    }
  }

  /**
   * Create instance using provided headers and signature bytes. Should be used
   * only by classes within the library.
   *
   * @param protectedHeader   a JwsHeader instance
   * @param unprotectedHeader a JwsHeader instance
   * @param signatureBytes    signature or HMAC
   * @return a JWS signature
   */
  static Signature getInstance(JwsHeader protectedHeader, JwsHeader unprotectedHeader, byte[] signatureBytes) {
    validateProtectedHeader(protectedHeader);
    Signature signature = new Signature();
    signature.protectedHeader = protectedHeader;
    signature.header = unprotectedHeader;
    signature.signature = signatureBytes;
    return signature;
  }

  /**
   * Get the protected JOSE header
   *
   * @return the protected JOSE header
   */
  public JwsHeader getProtectedHeader() {
    return protectedHeader;
  }

  /**
   * Get the unprotected JOSE header
   *
   * @return the unprotected JOSE header
   */
  public JwsHeader getHeader() {
    return header;
  }

  /**
   * Get the signature byte array
   *
   * @return signature byte array
   */
  public byte[] getSignatureBytes() {
    return signature;
  }

}
