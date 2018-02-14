package ch.keybridge.jose.jws;

import ch.keybridge.jose.JoseCryptoHeader;
import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import ch.keybridge.jose.jwk.JsonWebKey;
import ch.keybridge.jose.util.Base64Utility;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.jose.util.JsonMarshaller;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

import static ch.keybridge.jose.util.Base64Utility.toBase64Url;
import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * RFC 7515 § 7.2.1
 * The following members are defined for use in the JSON objects that
 * are elements of the "signatures" array:
 * protected
 * <p>
 * The "protected" member MUST be present and contain the value
 * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected
 * Header value is non-empty; otherwise, it MUST be absent.  These
 * Header Parameter values are integrity protected.
 * header
 * <p>
 * The "header" member MUST be present and contain the value JWS
 * Unprotected Header when the JWS Unprotected Header value is non-
 * empty; otherwise, it MUST be absent.  This value is represented as
 * an unencoded JSON object, rather than as a string.  These Header
 * Parameter values are not integrity protected.
 * signature
 * <p>
 * The "signature" member MUST be present and contain the value
 * BASE64URL(JWS Signature).
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JwsSignature {
  /**
   * The "protected" member MUST be present and contain the value
   * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected
   * Header value is non-empty; otherwise, it MUST be absent.  These
   * Header Parameter values are integrity protected.
   */
  @XmlElement(name = "protected")
  private JoseCryptoHeader protectedHeader;
  /**
   * The "header" member MUST be present and contain the value JWS
   * Unprotected Header when the JWS Unprotected Header value is non-
   * empty; otherwise, it MUST be absent.  This value is represented as
   * an unencoded JSON object, rather than as a string.  These Header
   * Parameter values are not integrity protected.
   */
  @XmlElement(name = "header")
  private JoseCryptoHeader unprotectedheader;
  /**
   * The "signature" member MUST be present and contain the value
   * BASE64URL(JWS Signature).
   */
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] signature;

  public static JwsSignature getInstance(byte[] payload, JsonWebKey key) throws IOException, GeneralSecurityException {
    JwsSignature signature = new JwsSignature();
    JoseCryptoHeader ph = new JoseCryptoHeader();
    ph.setAlg(key.getAlg());
    ph.setX5c(key.getX5c());
    ph.setX5t(key.getX5t());
    ph.setX5tS256(key.getX5tS256());
    ph.setX5u(key.getX5u());
    ph.setKid(key.getKid());
    signature.protectedHeader = ph;

    String protectedHeaderJson = JsonMarshaller.toJson(ph);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    signature.signature = CryptographyUtility.sign(fullPayload.getBytes(US_ASCII), key);
    return signature;
  }

  public static JwsSignature getInstance(byte[] payload, Key key, JoseCryptoHeader protectedHeader) throws IOException,
      GeneralSecurityException {
    return getInstance(payload, key, protectedHeader, null);
  }

  public static JwsSignature getInstance(byte[] payload, Key key, JoseCryptoHeader protectedHeader, JoseCryptoHeader
      unprotectedHeader) throws IOException, GeneralSecurityException {
    JwsSignature signature = new JwsSignature();
    signature.protectedHeader = protectedHeader;
    signature.unprotectedheader = unprotectedHeader;
    ESignatureAlgorithm algorithm = ESignatureAlgorithm.resolveAlgorithm(protectedHeader.getAlg());

    String protectedHeaderJson = JsonMarshaller.toJson(signature.protectedHeader);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    signature.signature = CryptographyUtility.sign(fullPayload.getBytes(US_ASCII), key, algorithm
        .getJavaAlgorithmName());
    return signature;
  }

  static JwsSignature getInstance(JoseCryptoHeader protectedHeader, JoseCryptoHeader unprotectedheader, byte[]
      signatureBytes) {
    JwsSignature signature = new JwsSignature();
    signature.protectedHeader = protectedHeader;
    signature.unprotectedheader = unprotectedheader;
    signature.signature = signatureBytes;
    return signature;
  }

  public JoseCryptoHeader getProtectedHeader() {
    return protectedHeader;
  }

  public JoseCryptoHeader getUnprotectedheader() {
    return unprotectedheader;
  }

  public boolean isValidSignature(String payload, Key key) throws IOException, GeneralSecurityException {
    return isValidSignature(payload.getBytes(Base64Utility.DEFAULT_CHARSET), key);
  }

  public boolean isValidSignature(byte[] payload, Key key) throws IOException, GeneralSecurityException {
    String protectedHeaderJson = JsonMarshaller.toJson(protectedHeader);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    ESignatureAlgorithm algorithm = ESignatureAlgorithm.resolveAlgorithm(protectedHeader.getAlg());
    return CryptographyUtility.validateSignature(signature, fullPayload.getBytes(US_ASCII), key, algorithm
        .getJavaAlgorithmName());
  }

  public boolean isValidSignature(byte[] payload, String secret) throws IOException, GeneralSecurityException {
    String protectedHeaderJson = JsonMarshaller.toJson(protectedHeader);
    String fullPayload = toBase64Url(protectedHeaderJson) + '.' + toBase64Url(payload);
    ESignatureAlgorithm algorithm = ESignatureAlgorithm.resolveAlgorithm(protectedHeader.getAlg());

    SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm.getJavaAlgorithmName());
    return CryptographyUtility.validateSignature(signature, fullPayload.getBytes(US_ASCII), key, algorithm
        .getJavaAlgorithmName());
  }

  public byte[] getSignature() {
    return signature;
  }

}
