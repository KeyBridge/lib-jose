package org.ietf.jose.jwt;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/12/2017
 */
public class JwtClaimsTest {

  @Test
  public void equals() throws IOException, Exception {
    ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC")).truncatedTo(ChronoUnit.SECONDS);

    JwtClaims claim = new JwtClaims();
    claim.withAudience("someAudience");
    claim.setIssuedAt(now);
    claim.setNotBefore(now.plusHours(1));
    claim.setExpiresAt(now.plusHours(2));
    claim.addClaim("privateName", "privateValue");

//    String json = new JsonbUtility().withFormatting(true).marshal(claim);
    String jsonDirect = claim.toJson();

//    System.out.println("  JsonbUtility.marshal : " + json);
//    System.out.println("  claim.toJson         : " + jsonDirect);
    // test json text
//    assertEquals(json, jsonDirect);
    // test object vs reconstituted object
//    JwtClaims reconstituted = new JsonbUtility().unmarshal(json, JwtClaims.class);
//    System.out.println("original      " + claim.toJson());
//    System.out.println("  with array " + reconstituted.getClaims() == null);
//    System.out.println("reconstituted " + reconstituted.toJson());
//    System.out.println("  with array " + reconstituted.getClaims() == null);
    /**
     * BUG: The JsonMarshaller FAILS to read or write JWT private claims.
     * <p>
     * TODO: Add a JSON adapter for the claims field.
     */
//    assertEquals(claim, new JsonbUtility().unmarshal(json, JwtClaims.class));
//    java.lang.AssertionError:
//    expected: org.ietf.jose.jwt.JwtClaims<{"aud":"someAudience","exp":1527964352,"nbf":1527960752,"iat":1527957152}>
//    but was : org.ietf.jose.jwt.JwtClaims<{"aud":"someAudience","exp":1527964352,"nbf":1527960752,"iat":1527957152}>
    // test object vs. directly reconstituted object
    JwtClaims reconstituted = JwtClaims.fromJson(jsonDirect);
    System.out.println("  original      " + claim.toJson());
    System.out.println("  reconstituted " + reconstituted.toJson());
    assertEquals(claim, reconstituted);
    System.out.println("JwtClaimsTest equals   OK ");
  }

  @Test
  public void testCustomClaims() throws IOException, Exception {
    JwtClaims claims = new JwtClaims();
    claims.addClaim("email", "foo@bar.com");
    claims.addClaim("friends", Arrays.asList("John", "Jack", "Jeremy"));
    claims.withClaim(ClaimType.email, "email@foo.bar");

    String json = claims.toJson();
    System.out.println("  toJson   " + json);
    JwtClaims deserialized = JwtClaims.fromJson(json);
    assertEquals(claims, deserialized);

    System.out.println("JwtClaimsTest testCustomClaims   OK ");
  }
}
