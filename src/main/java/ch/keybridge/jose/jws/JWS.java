package ch.keybridge.jose.jws;

import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.jwk.JWK;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class JWS {
  private static final Logger LOG = Logger.getLogger(JWS.class.getCanonicalName());
  private String payload;
  private List<JwsSignature> signatures = new ArrayList<>();

  public String getPayload() {
    return payload;
  }

  public void setPayload(String payload) {
    this.payload = payload;
    signatures.clear();
  }

  public List<JwsSignature> getSignatures() {
    return signatures;
  }

  public int getSignatureNum() {
    return signatures.size();
  }

  public void signWith(JWK key, ESignatureAlgorithm algorithm) throws Exception {
    signatures.add(JwsSignature.getInstance(payload, key, algorithm));
  }

  public JwsJsonFlattened getFlattened() throws Exception {
    if (getSignatureNum() == 0) {
      LOG.warning("No signatures");
      return new JwsJsonFlattened(null, null, payload, null);
    }
    if (getSignatureNum() > 1) LOG.warning("Additional signatures will be discarded when flattened");
    JwsSignature signature = signatures.get(0);
    return new JwsJsonFlattened(
        signature.getProtectedHeader(), signature.getUnprotectedheader(), payload, signature.getSignature());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    JWS jws = (JWS) o;

    if (payload != null ? !payload.equals(jws.payload) : jws.payload != null) return false;
    return signatures != null ? signatures.equals(jws.signatures) : jws.signatures == null;
  }

  @Override
  public int hashCode() {
    int result = payload != null ? payload.hashCode() : 0;
    result = 31 * result + (signatures != null ? signatures.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "JWSJson{" +
        "payload='" + payload + '\'' +
        ", signatures=" + signatures +
        '}';
  }
}
