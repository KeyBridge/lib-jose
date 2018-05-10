package ch.keybridge.jose;

import ch.keybridge.jose.jwe.JweBuilder;
import ch.keybridge.jose.jwe.JweJsonFlattened;
import ch.keybridge.jose.jws.ESignatureAlgorithm;
import ch.keybridge.jose.jws.JwsBuilder;
import ch.keybridge.jose.jws.JwsJsonFlattened;
import ch.keybridge.jose.util.JsonMarshaller;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 14/02/2018
 */
public class JOSE {

  private final static Logger LOG = Logger.getLogger(JOSE.class.getCanonicalName());

  public static JwsBuilder newJwsBuilder() {
    return JwsBuilder.getInstance();
  }

  public static JweBuilder newJweFlattenedBuilder() {
    return JweBuilder.getInstance();
  }

  public static <T> T unpackSignedAndEncryptedJson(String json, Class<T> type, PrivateKey receiverKey, PublicKey senderKey) {
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
    } catch (IOException | GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }

  public static <T> T unpackSignedAndEncryptedJson(String json, Class<T> type, String secret) {
    try {
      JweJsonFlattened jwe = JsonMarshaller.fromJson(json, JweJsonFlattened.class);
      String payload = jwe.decryptAsString(JweBuilder.createSecretKey(secret));

      JwsJsonFlattened jws = JsonMarshaller.fromJson(payload, JwsJsonFlattened.class);

      boolean signatureValid = jws.isSignatureValid(secret);
      if (!signatureValid) {
        return null;
      }
      String mainPayload = jws.getStringPayload();
      return JsonMarshaller.fromJson(mainPayload, type);
    } catch (IOException | GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }

  public static String signAndEncrypt(Object object, PrivateKey senderPrivateKey, PublicKey publicKey,
                                      String senderId) {
    try {
      String jsonPayload = JsonMarshaller.toJson(object);

      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setKid(senderId);

      JwsJsonFlattened jws = JwsBuilder.getInstance()
        .withStringPayload(jsonPayload)
        .withProtectedHeader(header)
        .sign(senderPrivateKey, ESignatureAlgorithm.RS256)
        .buildJsonFlattened();

      return JweBuilder.getInstance()
        .withStringPayload(jws.toJson())
        .buildJweJsonFlattened(publicKey)
        .toJson();
    } catch (IOException | GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }

  public static String signAndEncrypt(Object object, String secret, String senderId) {
    try {
      String jsonPayload = JsonMarshaller.toJson(object);

      JoseCryptoHeader header = new JoseCryptoHeader();
      header.setKid(senderId);

      JwsJsonFlattened jws = JwsBuilder.getInstance()
        .withStringPayload(jsonPayload)
        .withProtectedHeader(header)
        .sign(secret)
        .buildJsonFlattened();

      return JweBuilder.getInstance()
        .withStringPayload(jws.toJson())
        .buildJweJsonFlattened(secret)
        .toJson();
    } catch (IOException | GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }
}
