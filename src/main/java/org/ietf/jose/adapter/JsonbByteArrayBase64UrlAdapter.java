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
import org.ietf.jose.util.Base64Utility;

/**
 * Converts byte arrays into Base64URL-encoded strings and vice versa
 */
public class JsonbByteArrayBase64UrlAdapter implements JsonbAdapter<byte[], String> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(byte[] obj) throws Exception {
    return Base64Utility.toBase64Url(obj);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public byte[] adaptFromJson(String obj) throws Exception {
    return Base64Utility.fromBase64Url(obj);
  }
}
