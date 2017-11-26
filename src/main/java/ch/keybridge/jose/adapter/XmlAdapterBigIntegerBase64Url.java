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

import ch.keybridge.jose.util.EncodingUtility;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import java.math.BigInteger;

/**
 * Converts BigInteger instances into Base64URL-encoded strings and vice versa
 */
public class XmlAdapterBigIntegerBase64Url extends XmlAdapter<String, BigInteger> {

  @Override
  public String marshal(BigInteger v) throws Exception {
    return EncodingUtility.encodeBase64Url(toBytesUnsigned(v));
  }

  @Override
  public BigInteger unmarshal(String v) throws Exception {
    return new BigInteger(1, EncodingUtility.decodeBase64Url(v));
  }


  /**
   * Returns a byte array representation of the specified big integer
   * without the sign bit.
   *
   * Copied from <a href="https://commons.apache.org/proper/commons-codec/xref/org/apache/commons/codec/binary/Base64.html">
   * Apache Commons Codec</a>
   *
   * @param bigInt The big integer to be converted. Must not be
   *               {@code null}.
   * @return A byte array representation of the big integer, without the
   *         sign bit.
   */
  public static byte[] toBytesUnsigned(final BigInteger bigInt) {
    // Copied from Apache Commons Codec 1.8
    int bitlen = bigInt.bitLength();
    // round bitlen
    bitlen = ((bitlen + 7) >> 3) << 3;
    final byte[] bigBytes = bigInt.toByteArray();

    if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
      return bigBytes;
    }

    // set up params for copying everything but sign bit
    int startSrc = 0;
    int len = bigBytes.length;

    // if bigInt is exactly byte-aligned, just skip signbit in copy
    if ((bigInt.bitLength() % 8) == 0) {
      startSrc = 1;
      len--;
    }
    final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
    final byte[] resizedBytes = new byte[bitlen / 8];
    System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
    return resizedBytes;
  }
}
