package ch.keybridge.jose.adapter;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import java.time.Instant;

/**
 * Converts java.time.Instant objects to longs and vice versa
 */
public class XmlAdapterInstantLong extends XmlAdapter<Long, Instant> {
  @Override
  public Instant unmarshal(Long v) {
    return Instant.ofEpochMilli(v);
  }

  @Override
  public Long marshal(Instant v) {
    return v.toEpochMilli();
  }
}
