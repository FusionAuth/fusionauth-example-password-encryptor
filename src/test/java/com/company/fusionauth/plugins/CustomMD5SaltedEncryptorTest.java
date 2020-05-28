package com.company.fusionauth.plugins;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniel DeGroff
 */
public class CustomMD5SaltedEncryptorTest {

  @Test
  public void encrypt() {
    PasswordEncryptor encryptor = new CustomMD5SaltedEncryptor();
    String result = encryptor.encrypt("password", "4MTVxbvk8swI0ys2Lf4saeR3swRvn0f2", 1);
    Assert.assertEquals(result, "e0198a696980741ec49e2c56615fbc98".toUpperCase());
  }
}
