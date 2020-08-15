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

import java.io.IOException;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import org.ietf.jose.jws.JwsHeader;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonMarshaller;

/**
 * Converts byte arrays into Base64URL-encoded strings and vice versa
 */
public class XmlAdapterJwsHeader extends XmlAdapter<String, JwsHeader> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String marshal(JwsHeader v) throws IOException {
    String protectedHeaderJson = JsonMarshaller.toJson(v);
    return Base64Utility.toBase64Url(protectedHeaderJson);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JwsHeader unmarshal(String v) throws IOException {
    String json = Base64Utility.fromBase64UrlToString(v);
    return JsonMarshaller.fromJson(json, JwsHeader.class);
  }
}
