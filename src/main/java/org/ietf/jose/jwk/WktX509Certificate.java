package org.ietf.jose.jwk;

import java.util.Arrays;
import java.util.Base64;

public class WktX509Certificate {

  public byte[] data;

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    WktX509Certificate that = (WktX509Certificate) o;

    return Arrays.equals(data, that.data);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(data);
  }

  @Override
  public String toString() {
    return Base64.getEncoder().encodeToString(data);
  }
}
