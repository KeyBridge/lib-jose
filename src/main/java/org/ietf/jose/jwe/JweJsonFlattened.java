package org.ietf.jose.jwe;

import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.jwe.encryption.Encrypter;
import org.ietf.jose.jwa.JWEEncryptionAlgorithmType;
import org.ietf.jose.jwe.encryption.EncryptionResult;
import org.ietf.jose.jwa.JWEKeyAlgorithmType;
import org.ietf.jose.util.CryptographyUtility;
import org.ietf.jose.util.JsonMarshaller;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringTokenizer;
import javax.crypto.SecretKey;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import static org.ietf.jose.util.Base64Utility.*;
import static org.ietf.jose.util.JsonMarshaller.fromJson;
import static java.nio.charset.StandardCharsets.US_ASCII;

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
public class JweJsonFlattened {

  /**
   * Integrity-protected header contents
   */
  @XmlElement(name = "protected", required = true)
  private JweJoseHeader protectedHeader;
  /**
   * Non-integrity-protected header contents
   */
  @XmlElement(name = "unprotected", required = true)
  private JweJoseHeader unprotected;
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
   * Ciphertext contents
   */
  @XmlElement(name = "ciphertext")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] ciphertext;
  /**
   * Authentication tag contents
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

  public JweJsonFlattened() {
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
   * @throws IllegalArgumentException if the provided input is not a valid
   *                                  compact JWE string
   */
  public static JweJsonFlattened fromCompactForm(String text) throws IOException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 5) {
      throw new IllegalArgumentException("JWE compact form must have 5 elements separated by dots. Supplied string has " + tokenizer.countTokens() + ".");
    }
    JweJsonFlattened jwe = new JweJsonFlattened();
    String protectedHeaderJson = fromBase64UrlToString(tokenizer.nextToken());
    jwe.protectedHeader = fromJson(protectedHeaderJson, JweJoseHeader.class);
    jwe.encryptedKey = fromBase64Url(tokenizer.nextToken());
    jwe.initializationVector = fromBase64Url(tokenizer.nextToken());
    jwe.ciphertext = fromBase64Url(tokenizer.nextToken());
    jwe.authenticationTag = fromBase64Url(tokenizer.nextToken());
    jwe.additionalAuthenticationData = toBase64Url(protectedHeaderJson).getBytes(US_ASCII);
    return jwe;
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
  public static JweJsonFlattened getInstance(final byte[] payload,
                                             final JWEEncryptionAlgorithmType contentEnc,
                                             JWEKeyAlgorithmType keyMgmt,
                                             Key key,
                                             JweJoseHeader protectedHeader,
                                             JweJoseHeader uprotected) throws IOException, GeneralSecurityException {
    JweJsonFlattened jwe = new JweJsonFlattened();
    /**
     * Populate the protected header with mandatory information on how the
     * content and the content encryption key are encrypted
     */
    protectedHeader.setAlg(keyMgmt.getJoseAlgorithmName());
    protectedHeader.setContentEncryptionAlgorithm(contentEnc);
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
   * Get the integrity-protected header
   *
   * @return integrity-protected header
   */
  public JweJoseHeader getProtectedHeader() {
    return protectedHeader;
  }

  /**
   * Get the non-integrity-protected header
   *
   * @return non-integrity-protected header
   */
  public JweJoseHeader getUnprotected() {
    return unprotected;
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

  public byte[] decryptPayload(Key key) throws GeneralSecurityException {
    final JWEKeyAlgorithmType keyManagementAlgorithm = JWEKeyAlgorithmType.resolveAlgorithm(protectedHeader
      .getAlg());
    final SecretKey aesKey = (SecretKey) CryptographyUtility.unwrapKey(encryptedKey, key, keyManagementAlgorithm
                                                                       .getJavaAlgorithm(), "AES"); //todo
    /**
     * Developer note: Additional files may need to be downloaded and copied
     * into the Java installation security directory
     * https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
     */
    Encrypter encrypter = protectedHeader.getContentEncryptionAlgorithm().getEncrypter();
    return encrypter.decrypt(ciphertext, initializationVector, additionalAuthenticationData, authenticationTag, aesKey);
  }

  public String decryptAsString(Key key) throws GeneralSecurityException {
    byte[] bytes = decryptPayload(key);
    return fromBase64UrlToString(new String(bytes, US_ASCII));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    JweJsonFlattened that = (JweJsonFlattened) o;

    if (protectedHeader != null ? !protectedHeader.equals(that.protectedHeader) : that.protectedHeader != null) {
      return false;
    }
    if (unprotected != null ? !unprotected.equals(that.unprotected) : that.unprotected != null) {
      return false;
    }
    if (!Arrays.equals(encryptedKey, that.encryptedKey)) {
      return false;
    }
    if (!Arrays.equals(initializationVector, that.initializationVector)) {
      return false;
    }
    if (!Arrays.equals(ciphertext, that.ciphertext)) {
      return false;
    }
    if (!Arrays.equals(authenticationTag, that.authenticationTag)) {
      return false;
    }
    return Arrays.equals(additionalAuthenticationData, that.additionalAuthenticationData);
  }

  @Override
  public int hashCode() {
    int result = protectedHeader != null ? protectedHeader.hashCode() : 0;
    result = 31 * result + (unprotected != null ? unprotected.hashCode() : 0);
    result = 31 * result + Arrays.hashCode(encryptedKey);
    result = 31 * result + Arrays.hashCode(initializationVector);
    result = 31 * result + Arrays.hashCode(ciphertext);
    result = 31 * result + Arrays.hashCode(authenticationTag);
    result = 31 * result + Arrays.hashCode(additionalAuthenticationData);
    return result;
  }

  public String toJson() throws IOException {
    return JsonMarshaller.toJson(this);
  }

  @Override
  public String toString() {
    return "JweJsonFlattened{"
      + "protectedHeader=" + protectedHeader
      + ", unprotected=" + unprotected
      + ", encryptedKey=" + Arrays.toString(encryptedKey)
      + ", initializationVector=" + Arrays.toString(initializationVector)
      + ", ciphertext=" + Arrays.toString(ciphertext)
      + ", authenticationTag=" + Arrays.toString(authenticationTag)
      + ", additionalAuthenticationData=" + Arrays.toString(additionalAuthenticationData)
      + '}';
  }
}