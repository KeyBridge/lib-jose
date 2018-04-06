package ch.keybridge.jose;

import ch.keybridge.jose.jwe.JweJsonFlattened;
import ch.keybridge.jose.jws.ESignatureAlgorithm;
import ch.keybridge.jose.jws.JwsBuilder;
import ch.keybridge.jose.jws.JwsJsonFlattened;
import ch.keybridge.jose.util.JsonMarshaller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JOSE {
  public static JwsBuilder newJwsBuilder() {
    return JwsBuilder.getInstance();
  }

  public static <T> T unpackSignedAndEncryptedJson(String json, Class<T> type, PrivateKey receiverKey, PublicKey
      senderKey) {
    try {
      JweJsonFlattened jwe = JsonMarshaller.fromJson(json, JweJsonFlattened.class);
      String payload = jwe.decryptAsString(receiverKey);

      JwsJsonFlattened jws = JsonMarshaller.fromJson(payload, JwsJsonFlattened.class);

      boolean signatureValid = jws.getJwsSignature().isValidSignature(jws.getStringPayload(), senderKey);
      if (!signatureValid) {
        return null;
      }
      String mainPayload = jws.getStringPayload();
      return JsonMarshaller.fromJson(mainPayload, type);
    } catch (IOException e) {
      e.printStackTrace();
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }
    return null;
  }

  public static String signAndEncrypt(Object object, PrivateKey senderPrivateKey, PublicKey receiverPublicKey) {
    try {
      String jsonPayload = JsonMarshaller.toJson(object);

      JwsJsonFlattened jws = JwsBuilder.getInstance()
          .withStringPayload(jsonPayload)
          .sign(senderPrivateKey, ESignatureAlgorithm.RS256)
          .buildJsonFlattened();

      return JweJsonFlattened.getInstance(jws.toJson(), receiverPublicKey).toJson();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }
    return null;
  }
}
