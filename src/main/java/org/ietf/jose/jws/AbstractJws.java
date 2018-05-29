/* 
 * Copyright 2018 Key Bridge.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ietf.jose.jws;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.ietf.jose.adapter.XmlAdapterByteArrayBase64Url;
import org.ietf.jose.util.Base64Utility;

import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * RFC 7515 JSON Web Signature (JWS)
 * <p>
 * <p>
 * 7.2.1. General JWS JSON Serialization Syntax
 * <p>
 * The following members are defined for use in top-level JSON objects used for
 * the fully general JWS JSON Serialization syntax:
 * <p>
 * payload: The "payload" member MUST be present and contain the value
 * BASE64URL(JWS Payload).
 * <p>
 * A base class for JWS subclasses. Contains fields common to all JWS objects.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 02/01/2018
 */
@Data
@EqualsAndHashCode(callSuper = false)
public abstract class AbstractJws extends JsonSerializable {

  /**
   * The "payload" member MUST be present and contain the value BASE64URL(JWS
   * Payload).
   */
  @XmlJavaTypeAdapter(type = byte[].class, value = XmlAdapterByteArrayBase64Url.class)
  protected byte[] payload;

  public String getStringPayload() {
    return new String(payload, Base64Utility.DEFAULT_CHARSET);
  }
}
