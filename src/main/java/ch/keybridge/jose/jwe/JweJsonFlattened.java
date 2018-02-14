package ch.keybridge.jose.jwe;

import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import ch.keybridge.jose.jwe.encryption.EEncryptionAlgo;
import ch.keybridge.jose.jwe.encryption.EncryptionResult;
import ch.keybridge.jose.jwe.keymgmt.EKeyManagementAlgorithm;
import ch.keybridge.jose.util.CryptographyUtility;

import javax.crypto.SecretKey;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringTokenizer;

import static ch.keybridge.jose.util.Base64Utility.*;
import static ch.keybridge.jose.util.JsonMarshaller.fromJson;
import static ch.keybridge.jose.util.JsonMarshaller.toJson;
import static java.nio.charset.StandardCharsets.US_ASCII;

@XmlAccessorType(XmlAccessType.FIELD)
public class JweJsonFlattened {
  /**
   * Default algorithms
   */
  private static final EEncryptionAlgo CONTENT_ENC_ALGO = EEncryptionAlgo.A256GCM;
  @XmlElement(name = "protected", required = true)
  private JweJoseHeader protectedHeader;

  @XmlElement(name = "encypted_key")
  @XmlJavaTypeAdapter(type=byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] encryptedKey;

  @XmlElement(name = "iv")
  @XmlJavaTypeAdapter(type=byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] initializationVector;

  @XmlJavaTypeAdapter(type=byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] ciphertext;

  @XmlElement(name = "tag")
  @XmlJavaTypeAdapter(type=byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] authenticationTag;

  @XmlElement(name = "aad")
  @XmlJavaTypeAdapter(type=byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] additionalAuthenticationData;
  private JweJoseHeader uprotected;
  private static final EKeyManagementAlgorithm KEY_MGMT_ALGO = EKeyManagementAlgorithm.RSA_OAEP;

  /**
   *
   * Converts a JWE compact serialization string into a JWE instance
   *
   * In the JWE Compact Serialization, no JWE Shared Unprotected Header or
   * JWE Per-Recipient Unprotected Header are used.  In this case, the
   * JOSE Header and the JWE Protected Header are the same.
   * In the JWE Compact Serialization, a JWE is represented as the
   * concatenation:
   * <pre>
   * BASE64URL(UTF8(JWE Protected Header)) || ’.’ ||
   * BASE64URL(JWE Encrypted Key) || ’.’ ||
   * BASE64URL(JWE Initialization Vector) || ’.’ ||
   * BASE64URL(JWE Ciphertext) || ’.’ ||
   * BASE64URL(JWE Authentication Tag)
   * </pre>
   * See RFC 7516 Section 7.1 for more information about the JWE Compact
   * Serialization.
   *
   * @param text a valid compact JWE string
   * @return non-null JWE instance
   * @throws IllegalArgumentException if the provided input is not a valid compact JWE string
   */
  public static JweJsonFlattened fromCompactForm(String text) throws IOException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 5) {
      throw new IllegalArgumentException("JWE compact form must have 5 elements separated by dots. Supplied string " +
          "has " + tokenizer.countTokens() + ".");
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
   * @param payload byte array representing the data that is to be JWE-encrypted
   * @param publicKey a Key instance which is used to encrypt the random data encryption key
   * @return a valid JWE instance
   * @throws GeneralSecurityException thrown if requested algorithms are not available
   */
  public static JweJsonFlattened getInstance(byte[] payload, Key publicKey) throws IOException,
      GeneralSecurityException {
    return getInstance(payload, CONTENT_ENC_ALGO, KEY_MGMT_ALGO, publicKey, new JweJoseHeader(), null);
  }

  /**
   * Creates a JWE instance for the payload using the provided public key
   *
   * @param payload   data that is to be JWE-encrypted
   * @param publicKey a Key instance which is used to encrypt the random data encryption key
   * @return a valid JWE instance
   * @throws GeneralSecurityException thrown if requested algorithms are not available
   */
  public static JweJsonFlattened getInstance(String payload, Key publicKey) throws IOException,
      GeneralSecurityException {
    return getInstance(toBase64Url(payload).getBytes(US_ASCII), CONTENT_ENC_ALGO, KEY_MGMT_ALGO, publicKey, new
        JweJoseHeader(), null);
  }

  public static JweJsonFlattened getInstance(String payload, Key publicKey, JweJoseHeader protectedHeader,
                                             JweJoseHeader uprotected) throws IOException, GeneralSecurityException {
    return getInstance(toBase64Url(payload).getBytes(US_ASCII), CONTENT_ENC_ALGO, KEY_MGMT_ALGO, publicKey,
        protectedHeader, uprotected);
  }

  /**
   *
   * Creates a JWE instance for the payload using the provided public key
   * @param payload byte array representing the data that is to be JWE-encrypted
   * @param contentEnc Content encryption algorithm
   * @param keyMgmt key management algorithm
   * @param publicKey a Key instance which is used to encrypt the random data encryption key
   * @return a valid JWE instance
   * @throws GeneralSecurityException thrown if requested algorithms are not available
   */
  public static JweJsonFlattened getInstance(final byte[] payload, final EEncryptionAlgo contentEnc,
                                             EKeyManagementAlgorithm keyMgmt, Key publicKey, JweJoseHeader protectedHeader, JweJoseHeader uprotected) throws IOException,
      GeneralSecurityException {
    JweJsonFlattened jwe = new JweJsonFlattened();
    // Populate the protected header with mandatory information on how the content and the content encryption key are
    // encrypted
    protectedHeader.setAlg(keyMgmt.getJoseAlgorithmName());
    protectedHeader.setContentEncryptionAlgorithm(contentEnc);
    jwe.protectedHeader = protectedHeader;

    jwe.uprotected = uprotected;

    Key contentEncryptionKey = contentEnc.getEncrypter().generateKey();
    jwe.encryptedKey = CryptographyUtility.wrapKey(contentEncryptionKey, publicKey, keyMgmt.getJavaAlgorithm());
    /**
     * The default Additional Authentication Data can be the protected header
     */
    String headerJson = toJson(protectedHeader);
    jwe.additionalAuthenticationData = toBase64Url(headerJson).getBytes(US_ASCII);
    EncryptionResult encryptionResult = contentEnc.getEncrypter().encrypt(payload, null, jwe
        .additionalAuthenticationData, contentEncryptionKey);
    jwe.ciphertext = encryptionResult.getCiphertext();
    jwe.authenticationTag = encryptionResult.getAuthTag();
    jwe.initializationVector = encryptionResult.getIv();
    return jwe;
  }

  public JweJoseHeader getProtectedHeader() {
    return protectedHeader;
  }

  public JweJoseHeader getUprotected() {
    return uprotected;
  }

  /**
   * Converts a JWE instance into a single URL-safe string
   * <p>
   * In the JWE Compact Serialization, no JWE Shared Unprotected Header or
   * JWE Per-Recipient Unprotected Header are used.  In this case, the
   * JOSE Header and the JWE Protected Header are the same.
   * In the JWE Compact Serialization, a JWE is represented as the
   * concatenation:
   * <pre>
   * BASE64URL(UTF8(JWE Protected Header)) || ’.’ ||
   * BASE64URL(JWE Encrypted Key) || ’.’ ||
   * BASE64URL(JWE Initialization Vector) || ’.’ ||
   * BASE64URL(JWE Ciphertext) || ’.’ ||
   * BASE64URL(JWE Authentication Tag)
   * </pre>
   * See RFC 7516 Section 7.1 for more information about the JWE Compact
   * Serialization.
   *
   * @return non-null string
   */
  public String toCompactForm() throws IOException {
    return toBase64Url(toJson(protectedHeader)) + '.'
        + toBase64Url(encryptedKey) + '.'
        + toBase64Url(initializationVector) + '.'
        + toBase64Url(ciphertext) + '.'
        + toBase64Url(authenticationTag);
  }

  public byte[] decryptPayload(Key key) throws GeneralSecurityException {
    final EKeyManagementAlgorithm keyManagementAlgorithm = EKeyManagementAlgorithm.resolveAlgorithm(protectedHeader
        .getAlg());
    final SecretKey aesKey = (SecretKey) CryptographyUtility.unwrapKey(encryptedKey, key, keyManagementAlgorithm
        .getJavaAlgorithm(), "AES"); //todo
    /**
     * Developer note:
     * Additional files may need to be downloaded and copied into the Java installation security directory
     * https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
     */
//    Key aesKey = new SecretKeySpec(contentEncryptionKey, protectedHeader.getContentEncryptionAlgorithm()
// .getSecretKeyAlgorithm());
//    AlgorithmParameterSpec spec = protectedHeader.getContentEncryptionAlgorithm() == null
//    ? null : protectedHeader.getContentEncryptionAlgorithm().getAdditionalParameterGenerator().generateSpec
// (initializationVector);
//    return CryptographyUtility.decrypt(concatenateArrays(ciphertext, authenticationTag), aesKey, protectedHeader
//        .getContentEncryptionAlgorithm().getJavaAlgorithmName(), spec, additionalAuthenticationData);
    return protectedHeader.getContentEncryptionAlgorithm().getEncrypter().decrypt(ciphertext, initializationVector,
        additionalAuthenticationData, authenticationTag, aesKey);
  }

  public String decryptAsString(Key key) throws GeneralSecurityException {
    byte[] bytes = decryptPayload(key);
    return fromBase64UrlToString(new String(bytes, US_ASCII));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    JweJsonFlattened that = (JweJsonFlattened) o;

    if (protectedHeader != null ? !protectedHeader.equals(that.protectedHeader) : that.protectedHeader != null)
      return false;
    if (uprotected != null ? !uprotected.equals(that.uprotected) : that.uprotected != null) return false;
    if (!Arrays.equals(encryptedKey, that.encryptedKey)) return false;
    if (!Arrays.equals(initializationVector, that.initializationVector)) return false;
    if (!Arrays.equals(ciphertext, that.ciphertext)) return false;
    if (!Arrays.equals(authenticationTag, that.authenticationTag)) return false;
    return Arrays.equals(additionalAuthenticationData, that.additionalAuthenticationData);
  }

  @Override
  public int hashCode() {
    int result = protectedHeader != null ? protectedHeader.hashCode() : 0;
    result = 31 * result + (uprotected != null ? uprotected.hashCode() : 0);
    result = 31 * result + Arrays.hashCode(encryptedKey);
    result = 31 * result + Arrays.hashCode(initializationVector);
    result = 31 * result + Arrays.hashCode(ciphertext);
    result = 31 * result + Arrays.hashCode(authenticationTag);
    result = 31 * result + Arrays.hashCode(additionalAuthenticationData);
    return result;
  }

  @Override
  public String toString() {
    return "JweJsonFlattened{" +
        "protectedHeader=" + protectedHeader +
        ", uprotected=" + uprotected +
        ", encryptedKey=" + Arrays.toString(encryptedKey) +
        ", initializationVector=" + Arrays.toString(initializationVector) +
        ", ciphertext=" + Arrays.toString(ciphertext) +
        ", authenticationTag=" + Arrays.toString(authenticationTag) +
        ", additionalAuthenticationData=" + Arrays.toString(additionalAuthenticationData) +
        '}';
  }
}
