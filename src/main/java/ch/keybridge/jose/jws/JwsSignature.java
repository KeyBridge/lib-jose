package ch.keybridge.jose.jws;

import ch.keybridge.jose.JoseHeader;
import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.util.Base64Utility;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.jose.util.JsonMarshaller;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import static java.nio.charset.StandardCharsets.UTF_8;

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
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] signature;

  public JoseHeader getProtectedHeader() {
    return protectedHeader;
  }

  public JoseHeader getUnprotectedheader() {
    return unprotectedheader;
  }

  public static JwsSignature getInstance(String payload, JWK key, ESignatureAlgorithm algorithm) throws Exception {
    JwsSignature signature = new JwsSignature();
    JoseHeader ph = new JoseHeader();
    ph.setAlg(key.getAlg());
    ph.setX5c(key.getX5c());
    ph.setX5t(key.getX5t());
    ph.setX5tS256(key.getX5tS256());
    ph.setX5u(key.getX5u());
    ph.setKid(key.getKid());
    signature.protectedHeader = ph;

    String protectedHeaderJson = JsonMarshaller.toJson(signature.protectedHeader, JoseHeader.class);
    String fullPayload = Base64Utility.toBase64Url(protectedHeaderJson) + '.' + payload;
    signature.signature = CryptographyUtility.sign(fullPayload.getBytes(UTF_8), key, algorithm);
    return signature;
  }

  public byte[] getSignature() {
    return signature;
  }

}
