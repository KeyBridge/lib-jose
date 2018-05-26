/*
 * Copyright 2016 Key Bridge LLC.
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

import org.ietf.jose.jws.X509CertificateHeader;
import java.util.Base64;
import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * Converts X509CertificateHeader instances into Base64URL-encoded strings and vice
 versa
 */
public class XmlAdapterX509Certificate extends XmlAdapter<String, X509CertificateHeader> {

  @Override
  public String marshal(X509CertificateHeader v) {
    return v.toString();
  }

  @Override
  public X509CertificateHeader unmarshal(String v) {
    X509CertificateHeader certificate = new X509CertificateHeader();
    certificate.data = Base64.getDecoder().decode(v);
    return certificate;
  }
}
