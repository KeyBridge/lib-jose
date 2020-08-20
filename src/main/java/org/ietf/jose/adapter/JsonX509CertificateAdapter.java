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
package org.ietf.jose.adapter;

import java.util.Base64;
import javax.json.bind.adapter.JsonbAdapter;
import org.ietf.jose.jws.X5CHeaderParameter;

/**
 * Custom mapping for X5CHeaderParameter instances. Transforms to/from
 * base64-encoded strings.
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
 * <p>
 * Appendix B. "x5c" (X.509 Certificate Chain) Example
 * <p>
 * The JSON array below is an example of a certificate chain that could be used
 * as the value of an "x5c" (X.509 certificate chain) Header Parameter, per
 * Section 4.1.6 (with line breaks within values for display purposes only):
 * <pre>
 * ["MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVM
 * xITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR2
 * 8gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExM
 * TYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UE
 * CBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWR
 * keS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYW
 * RkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlc
 * nRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJ ...</pre>
 * <p>
 * This class is referenced by annotation in the `X5CHeaderParameter` class.
 *
 * @author Key Bridge
 * @since v0.10.0 created 2020-08-17
 */
public class JsonX509CertificateAdapter implements JsonbAdapter<X5CHeaderParameter, String> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(X5CHeaderParameter obj) throws Exception {
    return obj == null || obj.getData() == null
           ? null
           : new String(Base64.getMimeEncoder().encode(obj.getData()));
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public X5CHeaderParameter adaptFromJson(String obj) throws Exception {
    if (obj == null || obj.trim().isEmpty()) {
      return null;
    }
    X5CHeaderParameter certificate = new X5CHeaderParameter();
    certificate.setData(Base64.getMimeDecoder().decode(obj));
    return certificate;
  }
}
