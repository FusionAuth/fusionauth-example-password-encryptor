/*
 * Copyright (c) 2021, FusionAuth, All Rights Reserved
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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author Matthew Hartstonge
 */
public class ExampleArgon2idPasswordEncryptorTest {
    @Test(dataProvider = "hashes")
    public void encrypt(String password, String salt, int factor, String expected) {
        PasswordEncryptor encryptor = new ExampleArgon2idPasswordEncryptor();
        String actual = encryptor.encrypt(password, b64Encode(salt), factor);
        Assert.assertEquals(actual, expected);
    }

    @DataProvider(name = "hashes")
    public Object[][] hashes() {
        return new Object[][]{
                {"password123", "saltysalt", 1, "$argon2id$v=19$m=65536,t=1,p=4$c2FsdHlzYWx0$4FnTpZaINA9WWoTmhm1Y5BNP0ueQGQWWPIARybMRN64"},
                {"password123", "saltysalt", 2, "$argon2id$v=19$m=65536,t=2,p=4$c2FsdHlzYWx0$BmD1EnGoAaDtGRiQ4nlW+pGIvHIHT+tW1F8xaWdxDQE"},
                {"password123", "2qUAZD49DpdiOnxQqRHddpBg0Rfb36NM4ZPSDTLCz6cM2MWQx0", 3, "$argon2id$v=19$m=65536,t=3,p=4$MnFVQVpENDlEcGRpT254UXFSSGRkcEJnMFJmYjM2Tk00WlBTRFRMQ3o2Y00yTVdReDA$WFpsLuNnmVrfVO3TRw5p6mtvv3ryDbNzyHzY/CN8/ow"},
                {"password123", "2TR5SPOtQBW62Y1Ju6brUBmd1HlPyfOrGlakmvTUFC5q3JvT1e", 3, "$argon2id$v=19$m=65536,t=3,p=4$MlRSNVNQT3RRQlc2MlkxSnU2YnJVQm1kMUhsUHlmT3JHbGFrbXZUVUZDNXEzSnZUMWU$5P4NBHMf3gSsBbiQc2PVPDUiGNPAT4YWEwOTHwk3aCA"},
                {"password321", "2TR5SPOtQBW62Y1Ju6brUBmd1HlPyfOrGlakmvTUFC5q3JvT1e", 3, "$argon2id$v=19$m=65536,t=3,p=4$MlRSNVNQT3RRQlc2MlkxSnU2YnJVQm1kMUhsUHlmT3JHbGFrbXZUVUZDNXEzSnZUMWU$ZGS+lgDik0LcF2T5m9p7+8OhoH5oztUuo4Po4hruK5w"},
        };
    }

    private String b64Encode(String in) {
        return new String(Base64.getEncoder().encode(in.getBytes(StandardCharsets.UTF_8)));
    }
}
