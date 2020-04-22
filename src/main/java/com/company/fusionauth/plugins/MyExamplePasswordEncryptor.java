package com.company.fusionauth.plugins;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;

/**
 * @author Daniel DeGroff
 */
public class MyExamplePasswordEncryptor implements PasswordEncryptor {
  @Override
  public int defaultFactor() {
    // TODO : Set the default factor for this encryptor
    return 42;
  }

  @Override
  public String encrypt(String password, String salt, int factor) {
    // Do encrypting type stuff here and then return the hash.

    // TODO : This is not a hash, it is 12345. But you should return a hash.
    return "12345";
  }
}
