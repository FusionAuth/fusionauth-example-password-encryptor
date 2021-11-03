/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package com.mycompany.fusionauth.plugins;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;
import org.testng.Assert;
import org.testng.annotations.Test;
import static org.testng.AssertJUnit.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class ExamplePHPMD5SaltedPasswordEncryptorTest {
  private static final String Base64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  @Test
  public void encrypt() {
    // Test control input and output to ensure the hash is correct.
    PasswordEncryptor encryptor = new ExamplePHPMD5SaltedPasswordEncryptor();
    String hash = "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0";

    // Assert factor calculation is correct
    int factor = 1 << Base64.indexOf(hash.charAt(3));
    assertEquals(2048, factor);

    // Assert the password extracted correctly
    String password = hash.substring(12);
    assertEquals("eRo7ud9Fh4E2PdI0S3r.L0", password);

    // Assert the salt extracted correctly
    String salt = hash.substring(4, 12);
    assertEquals("IQRaTwmf", salt);

    // Assert the calculated hash
    String result = encryptor.encrypt("test12345", salt, factor);
    Assert.assertEquals(result, password);
  }
}
