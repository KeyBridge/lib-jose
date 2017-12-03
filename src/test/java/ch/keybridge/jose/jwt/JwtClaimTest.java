package ch.keybridge.jose.jwt;

import ch.keybridge.jose.util.JsonMarshaller;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.junit.Assert.assertEquals;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/12/2017
 */
public class JwtClaimTest {

  @Test
  public void equals() throws JAXBException {
    JwtClaim claim = new JwtClaim();
    claim.setAudience("someAudience");
    ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());
    claim.setIssuedAt(now.toInstant());
    claim.setNotBefore(now.plusHours(1).toInstant());
    claim.setExpirationTime(now.plusHours(2).toInstant());

    String json = JsonMarshaller.toJson(claim, JwtClaim.class);
    System.out.println(json);

    assertEquals(claim, JsonMarshaller.fromJson(json, JwtClaim.class));
  }
}