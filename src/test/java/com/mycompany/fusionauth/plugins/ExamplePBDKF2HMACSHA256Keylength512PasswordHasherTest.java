/*
 * Copyright (c) 2019-2022, FusionAuth, All Rights Reserved
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
 * @author Dan Moore
 */
public class ExamplePBDKF2HMACSHA256Keylength512PasswordHasherTest {
  @Test(dataProvider = "hashes")
  public void encrypt(String password, String salt, String hash) {
    ExamplePBDKF2HMACSHA256KeyLength512PasswordHasher encryptor = new ExamplePBDKF2HMACSHA256KeyLength512PasswordHasher();
    assertEquals(encryptor.encrypt(password, salt, 27500), hash);
  }

  @DataProvider(name = "hashes")
  public Object[][] hashes() {
    return new Object[][]{
        {"password", "jVqbuA9k2Mlo37OWXBMKLw==", "LjFqvhPuUHJdQvWIwVQfqxjeujAWqG/DVQRFoOv62/cTznl9ob4jwWwY6i1RrwGviu5iNPU5VIp03SxDyetyfw=="},
        {"password", "XnYZtiSCmFE5HF/ZplNCow==", "OFb32+cOm0sgtEcmNiGC83A27Sk1gb0fynv0RUXBfFXEJ/EieUPlx4uDAGA/q0/FkX2iHO45qqoIqBesiYMIUg=="},
    };
  }
}
