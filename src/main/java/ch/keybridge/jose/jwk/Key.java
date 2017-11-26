package ch.keybridge.jose.jwk;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface Key {
  boolean hasPrivateKey();
  PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException;
  PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException;
  KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException;
}
