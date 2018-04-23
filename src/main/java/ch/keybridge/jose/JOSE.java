package ch.keybridge.jose;

import ch.keybridge.jose.jwe.JweJsonFlattened;
import ch.keybridge.jose.jws.ESignatureAlgorithm;
import ch.keybridge.jose.jws.JwsBuilder;
import ch.keybridge.jose.jws.JwsJsonFlattened;
import ch.keybridge.jose.util.JsonMarshaller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
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
      LOG.log(Level.SEVERE, null, e);
    } catch (GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }

  public static String signAndEncrypt(Object object, PrivateKey senderPrivateKey, Key receiverPublicKeyOrSecretKey) {
    try {
      String jsonPayload = JsonMarshaller.toJson(object);

      JwsJsonFlattened jws = JwsBuilder.getInstance()
          .withStringPayload(jsonPayload)
          .sign(senderPrivateKey, ESignatureAlgorithm.RS256)
          .buildJsonFlattened();

      return JweJsonFlattened.getInstance(jws.toJson(), receiverPublicKeyOrSecretKey).toJson();
    } catch (IOException e) {
      LOG.log(Level.SEVERE, null, e);
    } catch (GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }

  public static String signAndEncrypt(Object object, PrivateKey senderPrivateKey, Key receiverPublicKeyOrSecretKey,
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

      return JweJsonFlattened.getInstance(jws.toJson(), receiverPublicKeyOrSecretKey).toJson();
    } catch (IOException e) {
      LOG.log(Level.SEVERE, null, e);
    } catch (GeneralSecurityException e) {
      LOG.log(Level.SEVERE, null, e);
    }
    return null;
  }
}
