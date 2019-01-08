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
package org.ietf.jose.jwe;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringTokenizer;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.adapter.XmlAdapterJweHeader;
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwe.encryption.EncryptionResult;
import org.ietf.jose.jws.JsonSerializable;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.ietf.jose.util.Base64Utility.*;

/**
 * 7.2.2. Flattened JWE JSON Serialization Syntax
 * <p>
 * The flattened JWE JSON Serialization syntax is based upon the general syntax,
 * but flattens it, optimizing it for the single-recipient case. It flattens it
 * by removing the "recipients" member and instead placing those members defined
 * for use in the "recipients" array (the "header" and "encrypted_key" members)
 * in the top-level JSON object (at the same level as the "ciphertext" member).
 * <p>
 * The "recipients" member MUST NOT be present when using this syntax. Other
 * than this syntax difference, JWE JSON Serialization objects using the
 * flattened syntax are processed identically to those using the general syntax.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JsonWebEncryption extends JsonSerializable {

  /**
   * Integrity-protected header contents
   */
  @XmlElement(name = "protected", required = true)
  @XmlJavaTypeAdapter(type = JweHeader.class, value = XmlAdapterJweHeader.class)
  private JweHeader protectedHeader;
  /**
   * Non-integrity-protected header contents
   */
  @XmlElement(name = "unprotected", required = true)
  private JweHeader unprotected;
  /**
   * Encrypted key contents
   */
  @XmlElement(name = "encrypted_key")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] encryptedKey;
  /**
   * Initialization vector contents
   */
  @XmlElement(name = "iv")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] initializationVector;
  /**
   * Ciphertext contents are encrypted plaintext.
   */
  @XmlElement(name = "ciphertext")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] ciphertext;
  /**
   * Authentication tag contents the first half (128 bits) of the HMAC output M
   * as the Authentication Tag output.
   * <p>
   * See RFC 7516 JSON Web Encryption (JWE) at B.7. Truncate HMAC Value to
   * Create Authentication Tag
   */
  @XmlElement(name = "tag")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] authenticationTag;
  /**
   * Additional authenticated data contents
   */
  @XmlElement(name = "aad")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] additionalAuthenticationData;

  public JsonWebEncryption() {
  }

  /**
   * Creates a JWE instance for the payload using the provided public key
   *
   * @param payload         byte array representing the data that is to be
   *                        JWE-encrypted
   * @param contentEnc      Content encryption algorithm
   * @param keyMgmt         key management algorithm
   * @param key             a Key instance which is used to encrypt the random
   *                        data encryption key
   * @param protectedHeader the JSON protected header, Populated with mandatory
   *                        information on how the content and the content
   *                        encryption key are encrypted
   * @param uprotected      the unprotected content
   * @return a valid JWE instance
   * @throws java.io.IOException      if the protectedHeader fails to marshal to
   *                                  JSON
   * @throws GeneralSecurityException thrown if requested algorithms are not
   *                                  available
   */
  public static JsonWebEncryption getInstance(final byte[] payload,
                                              final JweEncryptionAlgorithmType contentEnc,
                                              JweKeyAlgorithmType keyMgmt,
                                              Key key,
                                              JweHeader protectedHeader,
                                              JweHeader uprotected) throws IOException, GeneralSecurityException {
    JsonWebEncryption jwe = new JsonWebEncryption();
    /**
     * Populate the protected header with mandatory information on how the
     * content and the content encryption key are encrypted
     */
    protectedHeader.setAlg(keyMgmt.getJoseAlgorithmName());
    protectedHeader.setEnc(contentEnc);
    jwe.protectedHeader = protectedHeader;

    jwe.unprotected = uprotected;

    Key contentEncryptionKey = contentEnc.getEncrypter().generateKey();
    jwe.encryptedKey = CryptographyUtility.wrapKey(contentEncryptionKey, key, keyMgmt.getJavaAlgorithm());
    /**
     * The default Additional Authentication Data can be the protected header
     */
    String headerJson = JsonMarshaller.toJson(protectedHeader); // throws IOException
    jwe.additionalAuthenticationData = toBase64Url(headerJson).getBytes(US_ASCII);
    EncryptionResult encryptionResult = contentEnc.getEncrypter().encrypt(payload, null, jwe.additionalAuthenticationData, contentEncryptionKey);
    jwe.ciphertext = encryptionResult.getCiphertext();
    jwe.authenticationTag = encryptionResult.getAuthTag();
    jwe.initializationVector = encryptionResult.getIv();
    return jwe;
  }

  /**
   * Create instance from JSON string
   *
   * @param json JSON string
   * @return a JweJsonFlattened instance
   * @throws IOException in case of failure to deserialise the JSON string
   */
  public static JsonWebEncryption fromJson(String json) throws IOException {
    return JsonMarshaller.fromJson(json, JsonWebEncryption.class);
  }

  /**
   * Converts a JWE compact serialization string into a JWE instance
   * <p>
   * In the JWE Compact Serialization, no JWE Shared Unprotected Header or JWE
   * Per-Recipient Unprotected Header are used. In this case, the JOSE Header
   * and the JWE Protected Header are the same. In the JWE Compact
   * Serialization, a JWE is represented as the concatenation:
   * <pre>
   * BASE64URL(UTF8(JWE Protected Header)) || ’.’ ||
   * BASE64URL(JWE Encrypted Key) || ’.’ ||
   * BASE64URL(JWE Initialization Vector) || ’.’ ||
   * BASE64URL(JWE Ciphertext) || ’.’ ||
   * BASE64URL(JWE Authentication Tag)
   * </pre> See RFC 7516 Section 7.1 for more information about the JWE Compact
   * Serialization.
   *
   * @param text a valid compact JWE string
   * @return non-null JWE instance
   * @throws java.io.IOException      on serialization error
   * @throws IllegalArgumentException if the provided input is not a valid
   *                                  compact JWE string
   */
  public static JsonWebEncryption fromCompactForm(String text) throws IOException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 5) {
      throw new IllegalArgumentException("JWE compact form must have 5 elements separated by dots. Supplied string has " + tokenizer.countTokens() + ".");
    }
    JsonWebEncryption jwe = new JsonWebEncryption();
    String protectedHeaderJson = fromBase64UrlToString(tokenizer.nextToken());
    jwe.protectedHeader = JsonMarshaller.fromJson(protectedHeaderJson, JweHeader.class);
    jwe.encryptedKey = fromBase64Url(tokenizer.nextToken());
    jwe.initializationVector = fromBase64Url(tokenizer.nextToken());
    jwe.ciphertext = fromBase64Url(tokenizer.nextToken());
    jwe.authenticationTag = fromBase64Url(tokenizer.nextToken());
    jwe.additionalAuthenticationData = toBase64Url(protectedHeaderJson).getBytes(US_ASCII);
    return jwe;
  }

  /**
   * Converts a JWE instance into a single URL-safe string
   * <p>
   * In the JWE Compact Serialization, no JWE Shared Unprotected Header or JWE
   * Per-Recipient Unprotected Header are used. In this case, the JOSE Header
   * and the JWE Protected Header are the same. In the JWE Compact
   * Serialization, a JWE is represented as the concatenation:
   * <pre>
   * BASE64URL(UTF8(JWE Protected Header)) || ’.’ ||
   * BASE64URL(JWE Encrypted Key) || ’.’ ||
   * BASE64URL(JWE Initialization Vector) || ’.’ ||
   * BASE64URL(JWE Ciphertext) || ’.’ ||
   * BASE64URL(JWE Authentication Tag)
   * </pre> See RFC 7516 Section 7.1 for more information about the JWE Compact
   * Serialization.
   *
   * @return non-null string
   * @throws java.io.IOException on JSON marshal error
   */
  public String toCompactForm() throws IOException {
    return toBase64Url(JsonMarshaller.toJson(protectedHeader)) + '.'
      + toBase64Url(encryptedKey) + '.'
      + toBase64Url(initializationVector) + '.'
      + toBase64Url(ciphertext) + '.'
      + toBase64Url(authenticationTag);
  }

  public JweHeader getProtectedHeader() {
    return this.protectedHeader;
  }

  public JweHeader getUnprotected() {
    return this.unprotected;
  }

  public byte[] getEncryptedKey() {
    return this.encryptedKey;
  }

  public byte[] getInitializationVector() {
    return this.initializationVector;
  }

  public byte[] getCiphertext() {
    return this.ciphertext;
  }

  public byte[] getAuthenticationTag() {
    return this.authenticationTag;
  }

  public byte[] getAdditionalAuthenticationData() {
    return this.additionalAuthenticationData;
  }

  @Override
  public int hashCode() {
    int hash = 5;
    hash = 29 * hash + Arrays.hashCode(this.ciphertext);
    return hash;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    final JsonWebEncryption other = (JsonWebEncryption) obj;
    return Arrays.equals(this.ciphertext, other.ciphertext);
  }

  @Override
  protected boolean canEqual(Object other) {
    return other instanceof JsonWebEncryption;
  }

  @Override
  public String toString() {
    return "JsonWebEncryption(protectedHeader=" + this.getProtectedHeader()
      + ", unprotected=" + this.getUnprotected()
      + ", encryptedKey=" + java.util.Arrays.toString(this.getEncryptedKey())
      + ", initializationVector=" + java.util.Arrays.toString(this.getInitializationVector())
      + ", ciphertext=" + java.util.Arrays.toString(this.getCiphertext())
      + ", authenticationTag=" + java.util.Arrays.toString(this.getAuthenticationTag())
      + ", additionalAuthenticationData=" + java.util.Arrays.toString(this.getAdditionalAuthenticationData())
      + ")";
  }
}
