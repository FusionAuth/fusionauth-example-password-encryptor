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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author Daniel DeGroff
 *
 * hash = (password + salt)
 */
public class ExampleCustomMD5SaltedAlternativePasswordEncryptorTest {
  @Test
  public void encrypt() {
    // Test control input and output to ensure the hash is correct.
    PasswordEncryptor encryptor = new ExampleCustomMD5SaltedAlternativePasswordEncryptor();
    byte[] bytes = "thesaltiestsalt".getBytes(StandardCharsets.UTF_8);
    String encodedSalt = Base64.getEncoder().encodeToString(bytes);

    String result = encryptor.encrypt("password", encodedSalt, 1);
    Assert.assertEquals(result, "M9ymEsDFD7sAk2nX0Jz/p3RoZXNhbHRpZXN0c2FsdA==");
  }
}
