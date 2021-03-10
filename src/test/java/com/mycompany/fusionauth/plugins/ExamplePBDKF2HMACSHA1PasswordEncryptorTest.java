/*
 * Copyright (c) 2019, FusionAuth, All Rights Reserved
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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class ExamplePBDKF2HMACSHA1PasswordEncryptorTest {
  @Test(dataProvider = "hashes")
  public void encrypt(String password, String salt, String hash) {
    ExamplePBDKF2HMACSHA1PasswordEncryptor encryptor = new ExamplePBDKF2HMACSHA1PasswordEncryptor();
    assertEquals(encryptor.encrypt(password, salt, 10_000), hash);
  }

  @DataProvider(name = "hashes")
  public Object[][] hashes() {
    return new Object[][]{
        {"password123", "1484161696d0ca62390273b98846f49671cecd78", "4761D3392092F9CA6036B53DC92C6D7F3D597576"},
        {"password123", "ea95629c7954d73ea670f07a798e9fd4ab907593", "9480AD9A59CB5053B832BA5E731AFCD1F78068EC"},
    };
  }
}
