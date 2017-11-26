package ch.keybridge.jose;

import ch.keybridge.jose.io.JsonUtility;
import ch.keybridge.jose.jwe.JWE;
import ch.keybridge.jose.jwe.JweJoseHeader;
import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.jwk.JWKSet;
import ch.keybridge.jose.jws.JWS;
import ch.keybridge.jose.jwt.JwtClaim;

import javax.xml.bind.JAXBException;

public enum MarshallerSingleton {
  INSTANCE;

  public static MarshallerSingleton getInstance() {
    return INSTANCE;
  }

  private JsonUtility<JWS> jwsJsonUtility;
  private JsonUtility<JWE> jweJsonUtility;
  private JsonUtility<JWKSet> jwkSetJsonUtility;
  private JsonUtility<JWK> jwkJsonUtility;
  private JsonUtility<JweJoseHeader> jweHeaderJsonUtility;
  private JsonUtility<JwtClaim> jwtClaimJsonUtility;


  MarshallerSingleton() {
    try {
      jwkJsonUtility = new JsonUtility<>(JWK.class);
      jweJsonUtility = new JsonUtility<>(JWE.class);
      jwsJsonUtility = new JsonUtility<>(JWS.class);
      jwkSetJsonUtility = new JsonUtility<>(JWKSet.class);
      jweHeaderJsonUtility = new JsonUtility<>(JweJoseHeader.class);
      jwtClaimJsonUtility = new JsonUtility<JwtClaim>(JwtClaim.class);
    } catch (JAXBException e) {
      e.printStackTrace();
    }
  }

  public JsonUtility<JWS> getJwsJsonUtility() {
    return jwsJsonUtility;
  }

  public JsonUtility<JWE> getJweJsonUtility() {
    return jweJsonUtility;
  }

  public JsonUtility<JWKSet> getJwkSetJsonUtility() {
    return jwkSetJsonUtility;
  }

  public JsonUtility<JWK> getJwkJsonUtility() {
    return jwkJsonUtility;
  }

  public JsonUtility<JweJoseHeader> getJweHeaderJsonUtility() {
    return jweHeaderJsonUtility;
  }

  public JsonUtility<JwtClaim> getJwtClaimJsonUtility() {
    return jwtClaimJsonUtility;
  }
}
