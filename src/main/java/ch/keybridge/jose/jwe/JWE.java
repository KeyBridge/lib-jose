package ch.keybridge.jose.jwe;


import ch.keybridge.jose.JoseHeader;
import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import ch.keybridge.jose.algorithm.EContentEncryptionAlgorithm;
import ch.keybridge.jose.algorithm.EKeyManagementAlgorithm;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.jose.util.SecureRandomUtility;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringTokenizer;

import static ch.keybridge.jose.util.Base64Utility.*;
import static ch.keybridge.jose.util.JsonMarshaller.fromJson;
import static ch.keybridge.jose.util.JsonMarshaller.toJson;
import static java.nio.charset.StandardCharsets.US_ASCII;

@XmlAccessorType(XmlAccessType.FIELD)
public class JWE {
  @XmlElement(name = "protected")
  private JweJoseHeader protectedHeader;
  private JoseHeader uprotected;
  private JoseHeader perRecipientUprotected;

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

  /**
   * Default algorithms
   */
  private static final EContentEncryptionAlgorithm CONTENT_ENC_ALGO = EContentEncryptionAlgorithm.A256GCM;
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
  public static JWE fromCompactForm(String text) throws JAXBException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 5) {
      throw new IllegalArgumentException("JWE compact form must have 5 elements separated by dots. Supplied string " +
          "has " + tokenizer.countTokens() + ".");
    }
    JWE jwe = new JWE();
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
  public static JWE getInstance(byte[] payload, Key publicKey) throws JAXBException, GeneralSecurityException {
    return getInstance(payload, CONTENT_ENC_ALGO, KEY_MGMT_ALGO, publicKey);
  }

  /**
   * Creates a JWE instance for the payload using the provided public key
   *
   * @param payload   data that is to be JWE-encrypted
   * @param publicKey a Key instance which is used to encrypt the random data encryption key
   * @return a valid JWE instance
   * @throws GeneralSecurityException thrown if requested algorithms are not available
   */
  public static JWE getInstance(String payload, Key publicKey) throws JAXBException, GeneralSecurityException {
    return getInstance(toBase64Url(payload).getBytes(US_ASCII), CONTENT_ENC_ALGO, KEY_MGMT_ALGO, publicKey);
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
  public static JWE getInstance(final byte[] payload, final EContentEncryptionAlgorithm contentEnc,
                                EKeyManagementAlgorithm keyMgmt, Key publicKey) throws JAXBException,
      GeneralSecurityException {
    JWE jwe = new JWE();
    // Populate the protected header with mandatory information on how the content and the content encryption key are encrypted
    JweJoseHeader joseHeader = new JweJoseHeader();
    joseHeader.setAlg(keyMgmt.getJoseAlgorithmName());
    joseHeader.setContentEncryptionAlgorithm(contentEnc);

    jwe.protectedHeader = joseHeader;

    KeyGenerator generator = KeyGenerator.getInstance(contentEnc.getSecretKeyAlgorithm());
    generator.init(contentEnc.getEncryptionKeyBits());
    SecretKey contentEncryptionKey = generator.generateKey();
    jwe.encryptedKey = CryptographyUtility.encrypt(contentEncryptionKey.getEncoded(), publicKey, keyMgmt
        .getJavaAlgorithm());
    jwe.initializationVector = SecureRandomUtility.generate(contentEnc.getInitVectorBits());
    /**
     * The default Additional Authentication Data can be the protected header
     */
    String headerJson = toJson(joseHeader, JweJoseHeader.class);
    jwe.additionalAuthenticationData = toBase64Url(headerJson).getBytes(US_ASCII);
    byte[] cypherAndAuthTag = CryptographyUtility.encrypt(payload, contentEncryptionKey, contentEnc
            .getJavaAlgorithmName(),
        contentEnc.getAdditionalParameterGenerator() == null ? null : contentEnc
            .getAdditionalParameterGenerator().generateSpec(jwe.initializationVector), jwe
            .additionalAuthenticationData);
    jwe.ciphertext = Arrays.copyOf(cypherAndAuthTag, payload.length);
    jwe.authenticationTag = Arrays.copyOfRange(cypherAndAuthTag, payload.length, cypherAndAuthTag.length);
    return jwe;
  }

  /**
   * A utility method for array concatenation. Used to concatenate the ciphertext and authentication tag bytes
   * before decrypting.
   *
   * @param array1 first byte array
   * @param array2 second byte array
   * @return byte array with all elements from the first array, the those of the second array
   */
  private static byte[] concatenateArrays(byte[] array1, byte[] array2) {
    if (array1 == null || array1.length == 0) return array2;
    if (array2 == null || array2.length == 0) return array1;
    byte[] merged = new byte[array1.length + array2.length];
    System.arraycopy(array1, 0, merged, 0, array1.length);
    System.arraycopy(array2, 0, merged, array1.length, array2.length);
    return merged;
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
  public String toCompactForm() throws JAXBException {
    return toBase64Url(toJson(protectedHeader, JweJoseHeader.class)) + '.'
        + toBase64Url(encryptedKey) + '.'
        + toBase64Url(initializationVector) + '.'
        + toBase64Url(ciphertext) + '.'
        + toBase64Url(authenticationTag);
  }

  public byte[] decryptPayload(Key privateKey) throws GeneralSecurityException {
    final EKeyManagementAlgorithm keyManagementAlgorithm = EKeyManagementAlgorithm.resolveAlgorithm(protectedHeader.getAlg());
    final byte[] contentEncryptionKey = CryptographyUtility.decrypt(encryptedKey, privateKey, keyManagementAlgorithm
        .getJavaAlgorithm());
    /**
     * Developer note:
     * Additional files may need to be downloaded and copied into the Java installation security directory
     * https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
     */
    Key aesKey = new SecretKeySpec(contentEncryptionKey, protectedHeader.getContentEncryptionAlgorithm().getSecretKeyAlgorithm());
    AlgorithmParameterSpec spec = protectedHeader.getContentEncryptionAlgorithm() == null
    ? null : protectedHeader.getContentEncryptionAlgorithm().getAdditionalParameterGenerator().generateSpec(initializationVector);
    return CryptographyUtility.decrypt(concatenateArrays(ciphertext, authenticationTag), aesKey, protectedHeader
        .getContentEncryptionAlgorithm().getJavaAlgorithmName(), spec, additionalAuthenticationData);
  }

  public String decryptAsString(Key key) throws GeneralSecurityException {
    byte[] bytes = decryptPayload(key);
    return fromBase64UrlToString(new String(bytes, US_ASCII));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    JWE jwe = (JWE) o;

    if (protectedHeader != null ? !protectedHeader.equals(jwe.protectedHeader) : jwe.protectedHeader != null)
      return false;
    if (uprotected != null ? !uprotected.equals(jwe.uprotected) : jwe.uprotected != null) return false;
    if (perRecipientUprotected != null ? !perRecipientUprotected.equals(jwe.perRecipientUprotected) : jwe
        .perRecipientUprotected != null)
      return false;
    if (!Arrays.equals(encryptedKey, jwe.encryptedKey)) return false;
    if (!Arrays.equals(initializationVector, jwe.initializationVector)) return false;
    if (!Arrays.equals(ciphertext, jwe.ciphertext)) return false;
    if (!Arrays.equals(authenticationTag, jwe.authenticationTag)) return false;
    return Arrays.equals(additionalAuthenticationData, jwe.additionalAuthenticationData);
  }

  @Override
  public int hashCode() {
    int result = protectedHeader != null ? protectedHeader.hashCode() : 0;
    result = 31 * result + (uprotected != null ? uprotected.hashCode() : 0);
    result = 31 * result + (perRecipientUprotected != null ? perRecipientUprotected.hashCode() : 0);
    result = 31 * result + Arrays.hashCode(encryptedKey);
    result = 31 * result + Arrays.hashCode(initializationVector);
    result = 31 * result + Arrays.hashCode(ciphertext);
    result = 31 * result + Arrays.hashCode(authenticationTag);
    result = 31 * result + Arrays.hashCode(additionalAuthenticationData);
    return result;
  }

  @Override
  public String toString() {
    return "JWE{" +
        "protectedHeader=" + protectedHeader +
        ", uprotected=" + uprotected +
        ", perRecipientUprotected=" + perRecipientUprotected +
        ", encryptedKey=" + toBase64Url(encryptedKey) +
        ", initializationVector=" + toBase64Url(initializationVector) +
        ", ciphertext=" + toBase64Url(ciphertext) +
        ", authenticationTag=" + toBase64Url(authenticationTag) +
        ", additionalAuthenticationData=" + toBase64Url(additionalAuthenticationData) +
        '}';
  }
}
