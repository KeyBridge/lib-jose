# JCE Installation instructions

**Note**: The following instructions are NOT necessary for Oracle JRE/JDK distributions in the US.

For OpenJDK or for Non-US distributions: _Due to import control restrictions of some countries, the version of the JCE policy files that are bundled in the Java Runtime Environment allow "strong" but limited cryptography to be used. JCE has been through the U.S. export review process.  The JCE framework, along with the various JCE providers that come standard with it (SunJCE, SunEC, SunPKCS11, SunMSCAPI, etc), is exportable._

Basically: The default JRE supports encryption using up to 128 bit keys due to some foreign jurisdiction import restrictions. To support larger encryption keys (e.g. 256 bit) you must update your JRE with a policy file for your jurisdiction.

For JRE versions less than 9:

You must add (or replace) the files `local_policy.jar` and `US_export_policy.jar` to to suppport unlimited strength encryption. These are available for donwload from Oracle.

**Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files**

  * [JDK 6](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)
  * [JDK 7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
  * [JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
  
Extract the jar files from the zip archive and save them in `${java.home}/jre/lib/security/`.

See the [StackOverflow thread](https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters) for additional narrative on this issue.

For JDK versions 9 and above:

This is implemented using a configuration change. Either:

  * Uncomment line `#crypto.policy=unlimited` in `lib\security\java.security`. [Release notes](http://oracle.com/technetwork/java/javase/8u151-relnotes-3850493.html)
  * Call `Security.setProperty("crypto.policy", "unlimited")` in your application.


