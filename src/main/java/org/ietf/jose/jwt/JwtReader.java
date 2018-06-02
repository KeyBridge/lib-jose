package org.ietf.jose.jwt;

import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jws.JsonWebSignature;

import java.io.IOException;

/**
 * A container for the two different types of JSON Web Tokens: the encrypted and the signed.
 * The type can be found by calling getType() and the appropriate concrete object obtained
 * using getters.
 *
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 30/05/2018
 */
public class JwtReader {
  /**
   * The type of the JWT: signed or encrypted
   */
  private Type type;
  /**
   * If signed, the jsonWebSignature field holds the value
   */
  private JsonWebSignature jsonWebSignature;
  /**
   * If encrypted, the jsonWebEncryption field holds the value
   */
  private JsonWebEncryption jsonWebEncryption;

  /**
   * Private constructor because the class should be accessed via static readCompactForm method
   *
   * @see JwtReader#readCompactForm(String)
   */
  private JwtReader() {
  }

  /**
   * Parse a JWT in a compact form string
   *
   * @param compactForm a JWT string in compact foem
   * @return a parsed JWT object
   * @throws IOException              in case of failure to parse headers of the JWT
   * @throws IllegalArgumentException if the JWT (compact form) is not valid
   */
  public static JwtReader readCompactForm(String compactForm) throws IOException {
    final int dots = countDots(compactForm);
    JwtReader jwt = new JwtReader();
    if (dots == 2) {
      jwt.jsonWebSignature = JsonWebSignature.fromCompactForm(compactForm);
      jwt.type = Type.Signed;
    } else if (dots == 4) {
      jwt.jsonWebEncryption = JsonWebEncryption.fromCompactForm(compactForm);
      jwt.type = Type.Encrypted;
    } else {
      throw new IllegalArgumentException("Unable to parse JWT as JWS or JWE");
    }
    return jwt;
  }

  /**
   * Count how many dots there are in the token string
   *
   * @param string non-null string
   * @return number of '.' symbol occurrences in the string
   */
  private static int countDots(String string) {
    int dots = 0;
    for (int i = 0; i < string.length(); i++) {
      if (string.charAt(i) == '.') dots++;
    }
    return dots;
  }

  public Type getType() {
    return this.type;
  }

  public JsonWebSignature getJsonWebSignature() {
    return this.jsonWebSignature;
  }

  public JsonWebEncryption getJsonWebEncryption() {
    return this.jsonWebEncryption;
  }

  public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof JwtReader)) return false;
    final JwtReader other = (JwtReader) o;
    if (!other.canEqual((Object) this)) return false;
    final Object this$type = this.getType();
    final Object other$type = other.getType();
    if (this$type == null ? other$type != null : !this$type.equals(other$type)) return false;
    final Object this$jsonWebSignature = this.getJsonWebSignature();
    final Object other$jsonWebSignature = other.getJsonWebSignature();
    if (this$jsonWebSignature == null ? other$jsonWebSignature != null : !this$jsonWebSignature.equals
        (other$jsonWebSignature))
      return false;
    final Object this$jsonWebEncryption = this.getJsonWebEncryption();
    final Object other$jsonWebEncryption = other.getJsonWebEncryption();
    if (this$jsonWebEncryption == null ? other$jsonWebEncryption != null : !this$jsonWebEncryption.equals
        (other$jsonWebEncryption))
      return false;
    return true;
  }

  public int hashCode() {
    final int PRIME = 59;
    int result = 1;
    final Object $type = this.getType();
    result = result * PRIME + ($type == null ? 43 : $type.hashCode());
    final Object $jsonWebSignature = this.getJsonWebSignature();
    result = result * PRIME + ($jsonWebSignature == null ? 43 : $jsonWebSignature.hashCode());
    final Object $jsonWebEncryption = this.getJsonWebEncryption();
    result = result * PRIME + ($jsonWebEncryption == null ? 43 : $jsonWebEncryption.hashCode());
    return result;
  }

  protected boolean canEqual(Object other) {
    return other instanceof JwtReader;
  }

  public String toString() {
    return "JwtReader(type=" + this.getType() + ", jsonWebSignature=" + this.getJsonWebSignature() + ", " +
        "jsonWebEncryption=" + this.getJsonWebEncryption() + ")";
  }

  /**
   * The two different types of JSON Web Tokens: the encrypted and the signed.
   */
  public enum Type {
    Signed, Encrypted
  }
}
