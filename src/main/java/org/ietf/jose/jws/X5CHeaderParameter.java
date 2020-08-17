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

import javax.json.bind.annotation.JsonbTypeAdapter;
import org.ietf.jose.adapter.JsonbX509CertificateAdapter;

/**
 * RFC 7515 JSON Web Signature (JWS)
 * <p>
 * 4.1.6. "x5c" (X.509 Certificate Chain) Header Parameter
 * <p>
 * The "x5c" (X.509 certificate chain) Header Parameter contains the X.509
 * public key certificate or certificate chain [RFC5280] corresponding to the
 * key used to digitally sign the JWS. The certificate or certificate chain is
 * represented as a JSON array of certificate value strings. Each string in the
 * array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded)
 * DER [ITU.X690.2008] PKIX certificate value. The certificate containing the
 * public key corresponding to the key used to digitally sign the JWS MUST be
 * the first certificate. This MAY be followed by additional certificates, with
 * each subsequent certificate being the one used to certify the previous one.
 * The recipient MUST validate the certificate chain according to RFC 5280
 * [RFC5280] and consider the certificate or certificate chain to be invalid if
 * any validation failure occurs. Use of this Header Parameter is OPTIONAL.
 *
 * @author Key Bridge
 */
@JsonbTypeAdapter(JsonbX509CertificateAdapter.class)
public class X5CHeaderParameter {

  /**
   * The certificate or certificate chain is represented as a JSON array of
   * certificate value strings. Each string in the array is a base64-encoded
   * (Section 4 of [RFC4648] -- not base64url-encoded) DER [ITU.X690.2008] PKIX
   * certificate value.
   */
  private byte[] data;

  public X5CHeaderParameter() {
  }

  public byte[] getData() {
    return this.data;
  }

  public void setData(byte[] data) {
    this.data = data;
  }

}
