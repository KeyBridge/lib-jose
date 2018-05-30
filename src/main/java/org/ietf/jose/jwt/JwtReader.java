package org.ietf.jose.jwt;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.ietf.jose.jwe.JweJsonFlattened;
import org.ietf.jose.jws.FlattenedJsonSignature;

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
   * If signed, the jwsFlattenedObject field holds the value
   */
  private FlattenedJsonSignature jwsFlattenedObject;
  /**
   * If encrypted, the jweFlattenedObject field holds the value
   */
  private JweJsonFlattened jweFlattenedObject;

  /**
   * Parse a JWT in a compact form string
   *
   * @param compactForm a JWT string in compact foem
   * @return a parsed JWT object
   * @throws IOException              in case of failure to parse headers of the JWT
   * @throws IllegalArgumentException if the JWT (compact form) is not valid
   */
  public static JwtReader readCompactForm(String compactForm) throws IOException {
    final int dots = coundDots(compactForm);
    JwtReader jwt = new JwtReader();
    if (dots == 2) {
      jwt.jwsFlattenedObject = FlattenedJsonSignature.fromCompactForm(compactForm);
      jwt.type = Type.Signed;
    } else if (dots == 4) {
      jwt.jweFlattenedObject = JweJsonFlattened.fromCompactForm(compactForm);
      jwt.type = Type.Encrypted;
    } else {
      throw new IllegalArgumentException("Unable to parse JWT as JWS or JWE");
    }
    return jwt;
  }

  /**
   * Count how many dots there are in the token string
   *
   * @param string
   * @return
   */
  private static int coundDots(String string) {
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
