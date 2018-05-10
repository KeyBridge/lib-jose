package ch.keybridge.jose.adapter;

import java.time.Instant;
import javax.xml.bind.annotation.adapters.XmlAdapter;

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
