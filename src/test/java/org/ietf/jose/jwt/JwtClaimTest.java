package org.ietf.jose.jwt;

import org.ietf.jose.util.JsonMarshaller;
import org.junit.Test;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.junit.Assert.assertEquals;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/12/2017
 */
public class JwtClaimTest {

  @Test
  public void equals() throws IOException {
    JwtClaims claim = new JwtClaims();
    claim.setAudience("someAudience");
    ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());
    claim.setIssuedAt(now.toInstant());
    claim.setNotBefore(now.plusHours(1).toInstant());
    claim.setExpirationTime(now.plusHours(2).toInstant());

    String json = JsonMarshaller.toJson(claim);
    System.out.println(json);

    assertEquals(claim, JsonMarshaller.fromJson(json, JwtClaims.class));
  }
}