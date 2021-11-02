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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import io.fusionauth.plugin.spi.security.PasswordEncryptor;


/**
 * This is an example of an Argon2id hashing algorithm implemented in pure Java.
 *
 * <p>
 * This code is provided to assist in your deployment and management of FusionAuth. Use of this
 * software is not covered under the FusionAuth license agreement and is provided "as is" without
 * warranty. https://fusionauth.io/license
 * </p>
 *
 * @author Matthew Hartstonge
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9106"> RFC9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications </a>
 * @see <a href="https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf"> Original Argon2 Whitepaper </a>
 * @see <a href="https://www.bouncycastle.org/docs/docs1.5on/org/bouncycastle/crypto/params/Argon2Parameters.Builder.html"> Bouncy Castle Argon2Parameters </a>
 * @see <a href="https://www.bouncycastle.org/docs/docs1.5on/org/bouncycastle/crypto/generators/Argon2BytesGenerator.htmll"> Bouncy Castle Argon2BytesGenerator </a>
 */
public class ExampleArgon2idPasswordEncryptor implements PasswordEncryptor {
    /**
     * If much less memory is available, a uniformly safe option is
     * Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of
     * RAM), 128-bit salt, and 256-bit tag size.  This is the SECOND
     * RECOMMENDED option.
     * <p>
     * Refer: https://datatracker.ietf.org/doc/html/rfc9106#section-4
     */
    private static final int DEFAULT_TYPE = Argon2Parameters.ARGON2_id;
    private static final int DEFAULT_VERSION = Argon2Parameters.ARGON2_VERSION_13;
    private static final int DEFAULT_TIME_COST = 3;         // t=3           (3 Iterations)
    private static final int DEFAULT_MEMORY_COST = 1 << 16; // m=2^16        (64MiB Memory)
    private static final int DEFAULT_PARALLELISM = 4;       // p=4           (4 Lanes)
    private static final int DEFAULT_TAG_SIZE = 1 << 8;     // tag size=2^8  (256-bit hash size)
    private static final int DEFAULT_OFFSET = 0;

    @Override
    public int defaultFactor() {
        return DEFAULT_TIME_COST;
    }

    @Override
    public String encrypt(String password, String salt, int factor) {
        if (factor <= 0) {
            throw new IllegalArgumentException("Invalid factor value [" + factor + "]");
        }

        Argon2Parameters hasher = new Argon2Parameters
                .Builder(DEFAULT_TYPE)
                .withVersion(DEFAULT_VERSION)
                .withIterations(factor)
                .withMemoryAsKB(DEFAULT_MEMORY_COST)
                .withParallelism(DEFAULT_PARALLELISM)
                .withSalt(b64Decode(salt))
                .build();

        String hash = this.generateHashString(hasher, generateDigest(hasher, password));

        // zero out in-memory arrays that may store secrets...
        hasher.clear();

        return hash;
    }

    /**
     * generateDigest computes the Argon2 hashcode for the password from the provided argon2 configuration.
     *
     * @param params The configured Argon2 parameters.
     * @param password The password to compute a digest hashcode for.
     * @return digest The computed Argon2 hashcode from the provided parameters.
     */
    private byte[] generateDigest(Argon2Parameters params, String password) {
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        int bytesLength = DEFAULT_TAG_SIZE / 8;
        byte[] digest = new byte[bytesLength];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), digest, DEFAULT_OFFSET, bytesLength);

        return digest;
    }

    /**
     * generateHashString returns an Argon2 string from the configured argon parameters.
     *
     * The argon2 string has the format `$argon2{X}$v={V}$m={M},t={T},p={P}${salt}${digest}`
     * Where:
     * <ul>
     *     <li>{X} is the argon2 variant (`i`, `d`, or `id`)</li>
     *     <li>{V} is the argon2 version as an integer, which when rendered in hexadecimal denotes the argon2 version.
     *         For example, `v=19` equals `0x13`, that is, Argon2 1.3.</li>
     *     <li>{M} is the memory cost in kibibytes.</li>
     *     <li>{T} is the time cost in linear iterations.</li>
     *     <li>{P} is the amount of parallelism, that is, how many 'lanes' or threads are spawned.</li>
     *     <li>{salt} is the base64 encoded version of the salt bytes.</li>
     *     <li>{digest} is the base64 encoded version of the derived key bytes.</li>
     * </ul>
     *
     * @param params The configured Argon2 parameters.
     * @param digest The generated Argon2 computed digest hashcode.
     * @return hash The argon2 format string representation of the computed digest.
     */
    private String generateHashString(Argon2Parameters params, byte[] digest) {
        StringBuilder hash = new StringBuilder().append("$argon2");
        switch (params.getType()) {
            case Argon2Parameters.ARGON2_d:
                hash.append("d");
                break;

            case Argon2Parameters.ARGON2_i:
                hash.append("i");
                break;

            case Argon2Parameters.ARGON2_id:
                hash.append("id");
                break;
        }

        hash.append(String.format(
                "$v=%d$m=%d,t=%d,p=%d$%s$%s",
                params.getVersion(),
                params.getMemory(),
                params.getIterations(),
                params.getLanes(),
                b64Encode(params.getSalt()),
                b64Encode(digest)
        ));

        return hash.toString();
    }

    private String b64Encode(byte[] in) {
        return new String(Base64.getEncoder().withoutPadding().encode(in));
    }

    private byte[] b64Decode(String in) {
        return Base64.getDecoder().decode(in.getBytes(StandardCharsets.UTF_8));
    }
}
