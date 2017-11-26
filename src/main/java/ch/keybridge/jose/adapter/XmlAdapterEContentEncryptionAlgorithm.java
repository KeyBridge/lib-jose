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
package ch.keybridge.jose.adapter;

import ch.keybridge.jose.algorithm.EContentEncyptionAlgorithm;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * Converts EContentEncyptionAlgorithm enum values into Base64URL-encoded strings and vice versa
 */
public class XmlAdapterEContentEncryptionAlgorithm extends XmlAdapter<String, EContentEncyptionAlgorithm> {

  @Override
  public String marshal(EContentEncyptionAlgorithm v) throws Exception {
    return v.getJoseAlgorithmName();
  }

  @Override
  public EContentEncyptionAlgorithm unmarshal(String v) throws Exception {
    return EContentEncyptionAlgorithm.resolveAlgorithm(v);
  }
}
