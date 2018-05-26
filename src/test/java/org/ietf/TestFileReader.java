package org.ietf;

import java.io.*;
import java.util.Objects;
import java.util.stream.Collectors;


public class TestFileReader {

  /**
   * Reads a test resource file into a single String
   * @param path relative path from the test resources directory. Must start with '/'!
   * @return
   */
  public static String getTestCase(String path) {
    InputStream s = TestFileReader.class.getResourceAsStream(path);
    Objects.requireNonNull(s, "Resource missing: " + path);
    return new BufferedReader(new InputStreamReader(s)).lines().collect(Collectors.joining("\n"));
  }
}
