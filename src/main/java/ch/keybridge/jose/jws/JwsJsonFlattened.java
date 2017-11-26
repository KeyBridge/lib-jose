package ch.keybridge.jose.jws;

import ch.keybridge.jose.util.EncodingUtility;
import ch.keybridge.jose.JoseHeader;
import ch.keybridge.jose.io.JsonUtility;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

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
public class JwsJsonFlattened {
  @XmlElement(name = "protected")
  private final String protectedHeader;
  @XmlElement(name = "header")
  private final JoseHeader unprotectedHeader;
  private final String payload;
  private final String signature;

  public JwsJsonFlattened(JoseHeader protectedHeader, JoseHeader unprotectedHeader, String payload, String signature) throws Exception {
    JsonUtility<JoseHeader> readerWriter = new JsonUtility<>(JoseHeader.class);
    this.protectedHeader = EncodingUtility.encodeBase64Url(readerWriter.toJson(protectedHeader));
    this.unprotectedHeader = unprotectedHeader;
    this.payload = payload;
    this.signature = signature;
  }

  public String getProtectedHeader() {
    return protectedHeader;
  }

  public JoseHeader getUnprotectedHeader() {
    return unprotectedHeader;
  }

  public String getPayload() {
    return payload;
  }

  public String getSignature() {
    return signature;
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
   * @return
   */
  public String getCompactForm() {
    return protectedHeader + '.' + payload + '.' + signature;
  }
}
