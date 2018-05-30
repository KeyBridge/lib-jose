package org.ietf.jose.jwt;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class JwtBuilder {
  private JwtClaims claims;

  public static JwtBuilder createFor(JwtClaims claims) {
    JwtBuilder builder = new JwtBuilder();
    builder.claims = claims;
    return builder;
  }


}
