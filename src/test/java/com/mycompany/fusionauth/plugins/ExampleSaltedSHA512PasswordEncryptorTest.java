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
public class ExampleSaltedSHA512PasswordEncryptorTest {
  @Test
  public void encrypt() {
    // Test control input and output to ensure the hash is correct.
    PasswordEncryptor encryptor = new ExampleSaltedSHA512PasswordEncryptor();
    String result = encryptor.encrypt("password", "4MTVxbvk8swI0ys2Lf4saeR3swRvn0f2", 1);
    Assert.assertEquals(result, "GohyH5x4BaWvBhSNW4yTctmxY7azS7wqDOIENW1uOUHt6Qd2kDAimYweM9F95TH82OJHZIdm6kYirCtHpUdsIA==");
  }
}
