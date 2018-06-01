package org.ietf.jose.jwt;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
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
@EqualsAndHashCode
@ToString
@Getter
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

  /**
   * The two different types of JSON Web Tokens: the encrypted and the signed.
   */
  public enum Type {
    Signed, Encrypted
  }
}
