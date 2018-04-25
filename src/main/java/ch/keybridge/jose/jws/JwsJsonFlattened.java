package ch.keybridge.jose.jws;

import ch.keybridge.jose.JoseBase;
import ch.keybridge.jose.JoseCryptoHeader;
import ch.keybridge.jose.adapter.XmlAdapterByteArrayBase64Url;
import ch.keybridge.jose.util.Base64Utility;
import ch.keybridge.jose.util.JsonMarshaller;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * 7.2.2.  Flattened JWS JSON Serialization Syntax
 * <p>
 * The flattened JWS JSON Serialization syntax is based upon the general
 * syntax but flattens it, optimizing it for the single digital
 * signature/MAC case.  It flattens it by removing the "signatures"
 * member and instead placing those members defined for use in the
 * "signatures" array (the "protected", "header", and "signature"
 * members) in the top-level JSON object (at the same level as the
 * "payload" member).
 * <p>
 * The "signatures" member MUST NOT be present when using this syntax.
 * Other than this syntax difference, JWS JSON Serialization objects
 * using the flattened syntax are processed identically to those using
 * the general syntax.
 * <p>
 * In summary, the syntax of a JWS using the flattened JWS JSON
 * Serialization is as follows:
 * <pre>
 * {
 *  "payload":"[[payload contents]]",
 *  "protected":"[[integrity-protected header contents]]",
 *  "header":[[non-integrity-protected header contents]],
 *  "signature":"[[signature contents]]"
 * }
 * </pre>
 * See Appendix A.7 for an example JWS using the flattened JWS JSON
 * Serialization syntax.
 */

@XmlAccessorType(XmlAccessType.FIELD)
public class JwsJsonFlattened extends JwsJsonBase {
  @XmlElement(name = "protected")
  private JoseCryptoHeader protectedHeader;
  @XmlElement(name = "header")
  private JoseCryptoHeader unprotectedHeader;
  @XmlElement(name = "signature")
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  private byte[] signature;

  /**
   * Default constructor; required for JSON/XML serializers
   */
  public JwsJsonFlattened() {
  }

  public JwsJsonFlattened(JoseCryptoHeader protectedHeader, JoseCryptoHeader unprotectedHeader, byte[] payload,
                          byte[] signature) {
    this.protectedHeader = protectedHeader;
    this.unprotectedHeader = unprotectedHeader;
    this.payload = payload;
    this.signature = signature;
  }

  public JoseBase getProtectedHeader() {
    return protectedHeader;
  }

  public JoseBase getUnprotectedHeader() {
    return unprotectedHeader;
  }

  public byte[] getSignatureBytes() {
    return signature;
  }

  public JwsSignature getJwsSignature() {
    return JwsSignature.getInstance(protectedHeader, unprotectedHeader, signature);
  }

  /**
   * 7.1.  JWS Compact Serialization
   * <p>
   * The JWS Compact Serialization represents digitally signed or MACed
   * content as a compact, URL-safe string.  This string is:
   * <pre>
   * BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
   * BASE64URL(JWS Payload) || ’.’ ||
   * BASE64URL(JWS Signature)
   * </pre>
   * Only one signature/MAC is supported by the JWS Compact Serialization
   * and it provides no syntax to represent a JWS Unprotected Header
   * value.
   *
   * @return this JWS object encoded in compact serialization
   */
  public String getCompactForm() throws IOException {
    return Base64Utility.toBase64Url(JsonMarshaller.toJson(protectedHeader)) + '.' +
        Base64Utility.toBase64Url(payload) + '.' + Base64Utility.toBase64Url(signature);
  }

  public boolean isSignatureValid(String secret) throws IOException, GeneralSecurityException {
    JwsSignature signature = getJwsSignature();
    return signature.isValidSignature(payload, secret);
  }

  public static JwsJsonFlattened fromJson(String json) throws IOException {
    return JsonMarshaller.fromJson(json, JwsJsonFlattened.class);
  }

  public String toJson() throws IOException {
    return JsonMarshaller.toJson(this);
  }
}
