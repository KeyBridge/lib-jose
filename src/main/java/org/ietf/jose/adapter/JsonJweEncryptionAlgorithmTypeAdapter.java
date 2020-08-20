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
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;

/**
 * Json-B adapter for enumerated type.
 *
 * @author Key Bridge
 * @since v0.10.0 created 2020-08-18
 */
public class JsonJweEncryptionAlgorithmTypeAdapter implements JsonbAdapter<JweEncryptionAlgorithmType, String> {

  /**
   * {@inheritDoc}
   */
  @Override
  public String adaptToJson(JweEncryptionAlgorithmType obj) throws Exception {
    return obj == null ? null : obj.getJoseAlgorithmName();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public JweEncryptionAlgorithmType adaptFromJson(String obj) throws Exception {
    return obj == null || obj.isEmpty() ? null : JweEncryptionAlgorithmType.resolve(obj);
  }
}
