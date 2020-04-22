package com.company.fusionauth.plugins;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniel DeGroff
 */
public class MyExamplePasswordEncryptorTest {

  @Test
  public void encrypt() {
    // TODO : Assert that a plain text password matches an expected hash.
    PasswordEncryptor encryptor = new MyExamplePasswordEncryptor();
    Assert.assertEquals(encryptor.encrypt("my super secret password", "my salt", 24_000), "12345");
  }
}
