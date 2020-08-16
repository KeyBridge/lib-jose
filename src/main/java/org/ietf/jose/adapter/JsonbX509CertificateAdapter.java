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
 * Converts X5CHeaderParameter instances into Base64URL-encoded strings and vice
 * versa.
 */
public class JsonbX509CertificateAdapter implements JsonbAdapter<X5CHeaderParameter, String> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(X5CHeaderParameter obj) throws Exception {
    return obj == null ? null : obj.toString();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public X5CHeaderParameter adaptFromJson(String obj) throws Exception {
    X5CHeaderParameter certificate = new X5CHeaderParameter();
    certificate.setData(Base64.getDecoder().decode(obj));
    return certificate;
  }
}
