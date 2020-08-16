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

import javax.json.bind.adapter.JsonbAdapter;
import org.ietf.jose.jws.JwsHeader;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbReader;
import org.ietf.jose.util.JsonbWriter;

/**
 * Converts byte arrays into Base64URL-encoded strings and vice versa
 */
public class JsonbJwsHeaderAdapter implements JsonbAdapter<JwsHeader, String> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(JwsHeader obj) throws Exception {
    String protectedHeaderJson = new JsonbWriter().marshal(obj);
    return Base64Utility.toBase64Url(protectedHeaderJson);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JwsHeader adaptFromJson(String obj) throws Exception {
    String json = Base64Utility.fromBase64UrlToString(obj);
    return new JsonbReader().unmarshal(json, JwsHeader.class);
  }
}
