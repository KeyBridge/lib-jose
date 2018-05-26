package org.ietf.jose.jws;

import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.util.Base64Utility;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * A base class for JWS subclasses. Contains fields common to all JWS objects.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 02/01/2018
 */
public class JwsJsonBase {

  /**
   * The "payload" member MUST be present and contain the value BASE64URL(JWS
   * Payload).
   */
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  protected byte[] payload;

  /**
   * Get payload
   *
   * @return payload bytes
   */
  public byte[] getPayload() {
    return payload;
  }

  public String getStringPayload() {
    return new String(payload, Base64Utility.DEFAULT_CHARSET);
  }
}
