package com.company.fusionauth.plugins;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;

/**
 * 
 * @author Daniel DeGroff
 *
 */
public class CustomMD5SaltedEncryptor implements PasswordEncryptor {
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

      byte[] digest = (salt + password).getBytes(StandardCharsets.US_ASCII);
      for (int i = 0; i < factor; i++) {
        digest = messageDigest.digest(digest);
      }

      return DatatypeConverter.printHexBinary(digest);
    }
  }

