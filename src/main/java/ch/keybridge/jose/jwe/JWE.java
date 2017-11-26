package ch.keybridge.jose.jwe;


import ch.keybridge.jose.JoseHeader;
import ch.keybridge.jose.MarshallerSingleton;
import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import ch.keybridge.jose.algorithm.EContentEncyptionAlgorithm;
import ch.keybridge.jose.algorithm.EKeyManagementAlgorithm;
import ch.keybridge.jose.util.EncodingUtility;
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

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringTokenizer;

import static ch.keybridge.jose.util.EncodingUtility.decodeBase64Url;
import static ch.keybridge.jose.util.EncodingUtility.decodeBase64UrlToString;
import static ch.keybridge.jose.util.EncodingUtility.encodeBase64Url;

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
   * Converts a JWE instance into a single URL-safe string
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
   * @return non-null string
   */
  public String getCompactForm() throws JAXBException {
    return EncodingUtility.encodeBase64Url(MarshallerSingleton.getInstance().getJweHeaderJsonUtility().toJson(protectedHeader)) + '.'
        + encodeBase64Url(encryptedKey) + '.'
        + encodeBase64Url(initializationVector) + '.'
        + encodeBase64Url(ciphertext) + '.'
        + encodeBase64Url(authenticationTag);
  }

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
  public static JWE getInstanceFromCompactForm(String text) throws JAXBException {
    StringTokenizer tokenizer = new StringTokenizer(Objects.requireNonNull(text), ".");
    if (tokenizer.countTokens() != 5) {
      throw new IllegalArgumentException("JWE compact form must have 5 elements separated by dots. Supplied string " +
          "has " + tokenizer.countTokens() + ".");
    }
    JWE jwe = new JWE();
    String protectedHeaderJson = decodeBase64UrlToString(tokenizer.nextToken());
    jwe.protectedHeader = MarshallerSingleton.getInstance().getJweHeaderJsonUtility().fromJson(protectedHeaderJson);
    jwe.encryptedKey = decodeBase64Url(tokenizer.nextToken());
    jwe.initializationVector = decodeBase64Url(tokenizer.nextToken());
    jwe.ciphertext = decodeBase64Url(tokenizer.nextToken());
    jwe.authenticationTag = decodeBase64Url(tokenizer.nextToken());
    jwe.additionalAuthenticationData = EncodingUtility.encodeBase64UrlAscii(protectedHeaderJson);
    return jwe;
  }

  /**
   * Default algorithms
   */
  public static final EContentEncyptionAlgorithm CONTENT_ENCYPTION_ALGORITHM = EContentEncyptionAlgorithm.A256GCM;
  public static final EKeyManagementAlgorithm KEY_MANAGEMENT_ALGORITHM = EKeyManagementAlgorithm.RSA_OAEP;

  /**
   * Creates a JWE instance for the payload using the provided public key
   * @param payload byte array representing the data that is to be JWE-encrypted
   * @param publicKey a Key instance which is used to encrypt the random data encryption key
   * @return a valid JWE instance
   * @throws GeneralSecurityException thrown if requested algorithms are not available
   */
  public static JWE getInstance(byte[] payload, Key publicKey) throws JAXBException, GeneralSecurityException {
    return getInstance(payload, CONTENT_ENCYPTION_ALGORITHM, KEY_MANAGEMENT_ALGORITHM, publicKey);
  }

  /**
   *
   * Creates a JWE instance for the payload using the provided public key
   * @param payload byte array representing the data that is to be JWE-encrypted
   * @param contentEncyptionAlgorithm Content encryption algorithm
   * @param keyManagementAlgorithm key management algorithm
   * @param publicKey a Key instance which is used to encrypt the random data encryption key
   * @return a valid JWE instance
   * @throws GeneralSecurityException thrown if requested algorithms are not available
   */
  public static JWE getInstance(byte[] payload, EContentEncyptionAlgorithm contentEncyptionAlgorithm, EKeyManagementAlgorithm keyManagementAlgorithm, Key publicKey) throws JAXBException, GeneralSecurityException {
    JWE jwe = new JWE();
    // Populate the protected header with mandatory information on how the content and the content encryption key are encrypted
    JweJoseHeader joseHeader = new JweJoseHeader();
    joseHeader.setAlg(keyManagementAlgorithm.getJoseAlgorithmName());
    joseHeader.setContentEncryptionAlgorithm(contentEncyptionAlgorithm);

    jwe.protectedHeader = joseHeader;

//    final byte[] contentEncryptionKeyBytes = SecureRandomUtility.generate(contentEncyptionAlgorithm.getEncryptionKeyBits());
//    content

    KeyGenerator generator = KeyGenerator.getInstance(contentEncyptionAlgorithm.getSecretKeyAlgorithm());
    generator.init(contentEncyptionAlgorithm.getEncryptionKeyBits());
    SecretKey contentEncryptionKey = generator.generateKey(); //todo
    jwe.encryptedKey = CryptographyUtility.encrypt(contentEncryptionKey.getEncoded(), publicKey, keyManagementAlgorithm.getJavaAlgorithm());
    jwe.initializationVector = SecureRandomUtility.generate(contentEncyptionAlgorithm.getInitVectorBits());
    /**
     * The default Additional Authentication Data can be the protected header
     */
    String headerJson = MarshallerSingleton.getInstance().getJweHeaderJsonUtility().toJson(joseHeader);
    jwe.additionalAuthenticationData = EncodingUtility.encodeBase64UrlAscii(headerJson);
//    Key contentEncryptionKey = new SecretKeySpec(contentEncryptionKey.getEncoded(), );
    int cypherLen = payload.length;
    byte[] cypherAndAuthTag = CryptographyUtility.encrypt(payload, contentEncryptionKey, contentEncyptionAlgorithm
            .getJavaAlgorithmName(),
        contentEncyptionAlgorithm.getAdditionalParameterGenerator() == null ? null : contentEncyptionAlgorithm
            .getAdditionalParameterGenerator().generateSpec(jwe.initializationVector), jwe.additionalAuthenticationData);
    jwe.ciphertext = Arrays.copyOf(cypherAndAuthTag, cypherLen);
    jwe.authenticationTag = Arrays.copyOfRange(cypherAndAuthTag, cypherLen, cypherAndAuthTag.length);
    return jwe;
  }

  public byte[] decryptPayload(Key privateKey) throws Exception {
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

  private static byte[] concatenateArrays(byte[] array1, byte[] array2) {
    byte[] merged = new byte[array1.length + array2.length];
    System.arraycopy(array1, 0, merged, 0, array1.length);
    System.arraycopy(array2, 0, merged, array1.length, array2.length);
    return merged;
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
        ", encryptedKey=" + Arrays.toString(encryptedKey) +
        ", initializationVector=" + Arrays.toString(initializationVector) +
        ", ciphertext=" + Arrays.toString(ciphertext) +
        ", authenticationTag=" + Arrays.toString(authenticationTag) +
        ", additionalAuthenticationData=" + Arrays.toString(additionalAuthenticationData) +
        '}';
  }
}
