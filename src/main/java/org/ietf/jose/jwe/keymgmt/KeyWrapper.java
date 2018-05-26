package org.ietf.jose.jwe.keymgmt;

import java.security.Key;
import javax.crypto.SecretKey;

public interface KeyWrapper {

  byte[] wrapKey(Key key);

  SecretKey unwrapSecretKey(byte[] ciphertext);
}
