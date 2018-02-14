package ch.keybridge.jose.jwe.encryption;

import java.security.GeneralSecurityException;
import java.security.Key;

public interface Encrypter {
  Key generateKey() throws GeneralSecurityException;

  EncryptionResult encrypt(byte[] payload, byte[] iv, byte[] aad, Key key) throws GeneralSecurityException;

  byte[] decrypt(byte[] ciphertext, byte[] iv, byte[] aad, byte[] authTag, Key key) throws GeneralSecurityException;
}
