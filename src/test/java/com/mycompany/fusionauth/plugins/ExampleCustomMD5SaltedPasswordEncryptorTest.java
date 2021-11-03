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

/**
 * @author Daniel DeGroff
 */
public class ExampleCustomMD5SaltedPasswordEncryptorTest {
  @Test
  public void encrypt() {
    // Test control input and output to ensure the hash is correct.
    PasswordEncryptor encryptor = new ExampleCustomMD5SaltedPasswordEncryptor();
    String result = encryptor.encrypt("password", "4MTVxbvk8swI0ys2Lf4saeR3swRvn0f2", 1);
    Assert.assertEquals(result, "e0198a696980741ec49e2c56615fbc98".toUpperCase());
  }
}
