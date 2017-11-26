package ch.keybridge.jose.jws;

import ch.keybridge.jose.util.EncodingUtility;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.jose.JoseHeader;
import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.io.JsonUtility;
import ch.keybridge.jose.jwk.JWK;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

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
  @XmlElement(name = "protected")
  private JoseHeader protectedHeader;
  @XmlElement(name = "header")
  private JoseHeader unprotectedheader;
  private String signature;

  public JoseHeader getProtectedHeader() {
    return protectedHeader;
  }

  public JoseHeader getUnprotectedheader() {
    return unprotectedheader;
  }

  public String getSignature() {
    return signature;
  }

  public static JwsSignature getInstance(String payload, JWK key, ESignatureAlgorithm algorithm) throws Exception {
    JwsSignature signature = new JwsSignature();
    JoseHeader ph = new JoseHeader();
    ph.setAlg(key.getAlg());
//    ph.setCty();
    ph.setX5c(key.getX5c());
    ph.setX5t(key.getX5t());
    ph.setX5tS256(key.getX5tS256());
    ph.setX5u(key.getX5u());
    //todo other fields
    signature.protectedHeader = ph;

    JsonUtility<JoseHeader> readerWriter = new JsonUtility<>(JoseHeader.class);
    String protectedHeaderJson = readerWriter.toJson(signature.protectedHeader);
    String fullPayload = EncodingUtility.encodeBase64Url(protectedHeaderJson) + '.' + payload;
    byte[] payloadBytes = fullPayload.getBytes(EncodingUtility.UTF8);
    byte[] signatureBytes = CryptographyUtility.sign(payloadBytes, key, algorithm);
    signature.signature = EncodingUtility.encodeBase64Url(signatureBytes);
    return signature;
  }

}
