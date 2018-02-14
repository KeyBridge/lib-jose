package ch.keybridge.jose.jwe.keymgmt;

import javax.crypto.SecretKey;
import java.security.Key;

public interface KeyWrapper {
  byte[] wrapKey(Key key);

  SecretKey unwrapSecretKey(byte[] ciphertext);
}
