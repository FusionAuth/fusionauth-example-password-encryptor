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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;

/**
 * This is an example of a MD5 Salted hashing algorithm.
 * <pre>
 *   hash = (salt + password).getBytes()
 * </pre>
 *
 * <pre>
 * This code is provided to assist in your deployment and management of FusionAuth. Use of this
 * software is not covered under the FusionAuth license agreement and is provided "as is" without
 * warranty. https://fusionauth.io/license
 * </pre>
 *
 * @author Daniel DeGroff
 */
public class ExampleCustomMD5SaltedEncryptor implements PasswordEncryptor {
  private final static char[] HEX = "0123456789ABCDEF".toCharArray();

  @Override
  public int defaultFactor() {
    return 1;
  }

  @Override
  public String encrypt(String password, String salt, int factor) {
    if (factor <= 0) {
      throw new IllegalArgumentException("Invalid factor value [" + factor + "]");
    }

    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("No such algorithm [MD5]");
    }

    byte[] digest = (salt + password).getBytes(StandardCharsets.UTF_8);
    for (int i = 0; i < factor; i++) {
      digest = messageDigest.digest(digest);
    }

    return hex(digest);
  }

  private String hex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xFF;
      hexChars[i * 2] = HEX[v >>> 4];
      hexChars[i * 2 + 1] = HEX[v & 0x0F];
    }
    return new String(hexChars);
  }
}

