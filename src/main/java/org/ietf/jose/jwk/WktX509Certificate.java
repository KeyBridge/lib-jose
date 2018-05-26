package org.ietf.jose.jwk;

import java.util.Arrays;
import java.util.Base64;

/**
 * RFC 7515 JSON Web Signature (JWS)
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
 *
 * @author Key Bridge
 */
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
