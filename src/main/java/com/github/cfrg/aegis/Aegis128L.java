package com.github.cfrg.aegis;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Aegis128L is a class that implements the AEGIS-128L authenticated encryption
 * algorithm.
 */
public class Aegis128L {
        /**
         * Generates a random 128-bit key using a secure random number generator.
         *
         * @return the generated key as a byte array
         */
        public static byte[] keygen() {
                var key = new byte[16];
                var rng = new SecureRandom();
                rng.nextBytes(key);
                return key;
        }

        /**
         * Generates a random 128-bit nonce using a secure random number generator.
         *
         * @return the generated key as a byte array
         */
        public static byte[] noncegen() {
                var nonce = new byte[16];
                var rng = new SecureRandom();
                rng.nextBytes(nonce);
                return nonce;
        }

        AesBlock[] state = new AesBlock[8];

        int tag_length;

        public Aegis128L(final byte[] key, final byte[] nonce, final int tag_length) throws InvalidParameterException {
                if (tag_length != 16 && tag_length != 32) {
                        throw new InvalidParameterException("invalid tag length");
                }
                if (key.length != 16) {
                        throw new InvalidParameterException("invalid key length");
                }
                if (nonce.length != 16) {
                        throw new InvalidParameterException("invalid nonce length");
                }
                this.tag_length = tag_length;

                final byte[] c0_bytes = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59,
                                0x90 - 256,
                                0xe9 - 256, 0x79, 0x62 };
                final byte[] c1_bytes = { 0xdb - 256, 0x3d, 0x18, 0x55, 0x6d, 0xc2 - 256, 0x2f, 0xf1 - 256, 0x20, 0x11,
                                0x31,
                                0x42, 0x73, 0xb5 - 256, 0x28, 0xdd - 256 };
                final AesBlock c0 = new AesBlock(c0_bytes);
                final AesBlock c1 = new AesBlock(c1_bytes);

                final AesBlock key_block = new AesBlock(key);
                final AesBlock nonce_block = new AesBlock(nonce);
                var s = this.state;
                s[0] = key_block.xor(nonce_block);
                s[1] = new AesBlock(c1);
                s[2] = new AesBlock(c0);
                s[3] = new AesBlock(c1);
                s[4] = key_block.xor(nonce_block);
                s[5] = key_block.xor(c0);
                s[6] = key_block.xor(c1);
                s[7] = key_block.xor(c0);

                for (int i = 0; i < 10; i++) {
                        this.update(nonce_block, key_block);
                }
        }

        /**
         * Encrypts a message with associated data.
         *
         * @param msg the message to encrypt
         * @param ad  the associated data
         * @return the authenticated ciphertext and a detached tag
         */
        public AuthenticatedCiphertext encryptDetached(final byte[] msg, final byte[] ad) {
                var ciphertext = new byte[msg.length];
                var i = 0;
                if (ad != null) {
                        for (; i + 32 <= ad.length; i += 32) {
                                this.absorb(Arrays.copyOfRange(ad, i, i + 32));
                        }
                        if (ad.length % 32 != 0) {
                                var pad = new byte[32];
                                Arrays.fill(pad, (byte) 0);
                                for (var j = 0; j < ad.length % 32; j++) {
                                        pad[j] = ad[i + j];
                                }
                                this.absorb(pad);
                        }
                }
                if (msg != null) {
                        i = 0;
                        for (; i + 32 <= msg.length; i += 32) {
                                var ci = this.enc(Arrays.copyOfRange(msg, i, i + 32));
                                for (var j = 0; j < 32; j++) {
                                        ciphertext[i + j] = ci[j];
                                }
                        }
                        if (msg.length % 32 != 0) {
                                var pad = new byte[32];
                                Arrays.fill(pad, (byte) 0);
                                for (var j = 0; j < msg.length % 32; j++) {
                                        pad[j] = msg[i + j];
                                }
                                var ci = this.enc(pad);
                                for (var j = 0; j < msg.length % 32; j++) {
                                        ciphertext[i + j] = ci[j];
                                }
                        }
                }
                final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);

                return new AuthenticatedCiphertext(ciphertext, tag);
        }

        /**
         * Encrypts a message with associated data.
         *
         * @param msg the message to encrypt
         * @param ad  the associated data
         * @return the authenticated ciphertext that includes the tag
         */
        public byte[] encrypt(final byte[] msg, final byte[] ad) {
                var res = this.encryptDetached(msg, ad);
                var ciphertext = new byte[res.ct.length + res.tag.length];
                for (var i = 0; i < res.ct.length; i++) {
                        ciphertext[i] = res.ct[i];
                }
                for (var i = 0; i < res.tag.length; i++) {
                        ciphertext[res.ct.length + i] = res.tag[i];
                }
                return ciphertext;
        }

        /**
         * Decrypts a message with associated data.
         *
         * @param ac the authenticated ciphertext and detached tag
         * @param ad the associated data
         * @return the decrypted message
         * @throws VerificationFailedException if the tag verification fails
         */
        public byte[] decryptDetached(final AuthenticatedCiphertext ac, final byte[] ad)
                        throws VerificationFailedException {
                var i = 0;
                if (ad != null) {
                        for (; i + 32 <= ad.length; i += 32) {
                                this.absorb(Arrays.copyOfRange(ad, i, i + 32));
                        }
                        if (ad.length % 32 != 0) {
                                var pad = new byte[32];
                                Arrays.fill(pad, (byte) 0);
                                for (var j = 0; j < ad.length % 32; j++) {
                                        pad[j] = ad[i + j];
                                }
                                this.absorb(pad);
                        }
                }
                var msg = new byte[ac.ct.length];
                i = 0;
                for (; i + 32 <= ac.ct.length; i += 32) {
                        var xi = this.dec(Arrays.copyOfRange(ac.ct, i, i + 32));
                        for (var j = 0; j < 32; j++) {
                                msg[i + j] = xi[j];
                        }
                }
                if (ac.ct.length % 32 != 0) {
                        var xi = this.decLast(Arrays.copyOfRange(ac.ct, i, ac.ct.length));
                        for (var j = 0; j < ac.ct.length % 32; j++) {
                                msg[i + j] = xi[j];
                        }
                }
                final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);
                var dt = (byte) 0;
                for (var j = 0; j < tag.length; j++) {
                        dt |= tag[j] ^ ac.tag[j];
                }
                if (dt != 0) {
                        throw new VerificationFailedException("verification failed");
                }
                return msg;
        }

        /**
         * Decrypts the given ciphertext using Aegis128L algorithm.
         * 
         * @param ciphertext The ciphertext (which includes the tag) to be decrypted.
         * @param ad         The associated data used for decryption.
         * @return The decrypted plaintext.
         * @throws VerificationFailedException If the ciphertext is truncated or
         *                                     decryption fails.
         */
        public byte[] decrypt(final byte[] ciphertext, final byte[] ad) throws VerificationFailedException {
                if (ciphertext.length < this.tag_length) {
                        throw new VerificationFailedException("truncated ciphertext");
                }
                var ct = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - this.tag_length);
                var tag = Arrays.copyOfRange(ciphertext, ciphertext.length - this.tag_length, ciphertext.length);
                return this.decryptDetached(new AuthenticatedCiphertext(ct, tag), ad);
        }

        @Override
        public String toString() {
                return "Aegis128L [state=" + Arrays.toString(state) + ", tag_length=" + tag_length + "]";
        }

        // Reusable temporary block to avoid allocations in update method
        private final AesBlock tmpBlock = new AesBlock(0, 0, 0, 0);

        protected void update(final AesBlock m0, final AesBlock m1) {
                var s = this.state;

                // Save s[7] to temporary block
                tmpBlock.a = s[7].a;
                tmpBlock.b = s[7].b;
                tmpBlock.c = s[7].c;
                tmpBlock.d = s[7].d;

                // Perform state update using non-allocating methods
                s[6].encryptInto(s[7], s[7]);
                s[5].encryptInto(s[6], s[6]);
                s[4].encryptInto(s[5], s[5]);
                s[3].encryptInto(s[4], s[4]);
                s[2].encryptInto(s[3], s[3]);
                s[1].encryptInto(s[2], s[2]);
                s[0].encryptInto(s[1], s[1]);
                tmpBlock.encryptInto(s[0], s[0]);

                // Apply message mixing
                m1.xorInto(s[4], s[4]);
                m0.xorInto(s[0], s[0]);
        }

        // Reusable objects for absorb method
        private final byte[] absorbBuffer1 = new byte[16];
        private final byte[] absorbBuffer2 = new byte[16];
        private final AesBlock absorbBlock1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock absorbBlock2 = new AesBlock(0, 0, 0, 0);

        protected void absorb(byte[] ai) {
                assert ai.length == 32;

                // Copy data into reusable buffers
                System.arraycopy(ai, 0, absorbBuffer1, 0, 16);
                System.arraycopy(ai, 16, absorbBuffer2, 0, 16);

                // Load data into reusable AesBlock objects
                absorbBlock1.a = ((absorbBuffer1[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[0 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[0 * 4 + 3] & 0xff) << 24);
                absorbBlock1.b = ((absorbBuffer1[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[1 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[1 * 4 + 3] & 0xff) << 24);
                absorbBlock1.c = ((absorbBuffer1[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[2 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[2 * 4 + 3] & 0xff) << 24);
                absorbBlock1.d = ((absorbBuffer1[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[3 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[3 * 4 + 3] & 0xff) << 24);

                absorbBlock2.a = ((absorbBuffer2[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[0 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[0 * 4 + 3] & 0xff) << 24);
                absorbBlock2.b = ((absorbBuffer2[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[1 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[1 * 4 + 3] & 0xff) << 24);
                absorbBlock2.c = ((absorbBuffer2[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[2 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[2 * 4 + 3] & 0xff) << 24);
                absorbBlock2.d = ((absorbBuffer2[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[3 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[3 * 4 + 3] & 0xff) << 24);

                this.update(absorbBlock1, absorbBlock2);
        }

        // Reusable objects for enc method
        private final AesBlock encZ0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock encZ1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock encT0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock encT1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock encTmp = new AesBlock(0, 0, 0, 0);
        private final byte[] encBuffer = new byte[32];
        private final byte[] encOutBuffer1 = new byte[16];
        private final byte[] encOutBuffer2 = new byte[16];

        protected byte[] enc(byte[] xi) {
                assert xi.length == 32;
                var s = this.state;

                // Compute z0 = s[6] ⊕ s[1] ⊕ (s[2] & s[3]) without allocations
                s[2].andInto(s[3], encTmp);
                s[6].xorInto(s[1], encZ0);
                encTmp.xorInto(encZ0, encZ0);

                // Compute z1 = s[2] ⊕ s[5] ⊕ (s[6] & s[7]) without allocations
                s[6].andInto(s[7], encTmp);
                s[2].xorInto(s[5], encZ1);
                encTmp.xorInto(encZ1, encZ1);

                // Load input into t0, t1 without array copying
                System.arraycopy(xi, 0, absorbBuffer1, 0, 16);
                System.arraycopy(xi, 16, absorbBuffer2, 0, 16);

                encT0.a = ((absorbBuffer1[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[0 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[0 * 4 + 3] & 0xff) << 24);
                encT0.b = ((absorbBuffer1[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[1 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[1 * 4 + 3] & 0xff) << 24);
                encT0.c = ((absorbBuffer1[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[2 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[2 * 4 + 3] & 0xff) << 24);
                encT0.d = ((absorbBuffer1[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[3 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[3 * 4 + 3] & 0xff) << 24);

                encT1.a = ((absorbBuffer2[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[0 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[0 * 4 + 3] & 0xff) << 24);
                encT1.b = ((absorbBuffer2[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[1 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[1 * 4 + 3] & 0xff) << 24);
                encT1.c = ((absorbBuffer2[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[2 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[2 * 4 + 3] & 0xff) << 24);
                encT1.d = ((absorbBuffer2[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[3 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[3 * 4 + 3] & 0xff) << 24);

                // XOR and convert to bytes without allocations
                encT0.xorInto(encZ0, encTmp);
                encTmp.toBytes(encOutBuffer1);

                encT1.xorInto(encZ1, encTmp);
                encTmp.toBytes(encOutBuffer2);

                // Update state
                this.update(encT0, encT1);

                // Create output array reusing the buffer
                System.arraycopy(encOutBuffer1, 0, encBuffer, 0, 16);
                System.arraycopy(encOutBuffer2, 0, encBuffer, 16, 16);

                return encBuffer;
        }

        // Reusable objects for dec method
        private final AesBlock decZ0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decZ1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decT0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decT1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decOut0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decOut1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decTmp = new AesBlock(0, 0, 0, 0);
        private final byte[] decBuffer = new byte[32];

        protected byte[] dec(byte[] ci) {
                assert ci.length == 32;
                var s = this.state;

                // Compute z0 = s[6] ⊕ s[1] ⊕ (s[2] & s[3]) without allocations
                s[2].andInto(s[3], decTmp);
                s[6].xorInto(s[1], decZ0);
                decTmp.xorInto(decZ0, decZ0);

                // Compute z1 = s[2] ⊕ s[5] ⊕ (s[6] & s[7]) without allocations
                s[6].andInto(s[7], decTmp);
                s[2].xorInto(s[5], decZ1);
                decTmp.xorInto(decZ1, decZ1);

                // Load input into t0, t1 without array copying
                System.arraycopy(ci, 0, absorbBuffer1, 0, 16);
                System.arraycopy(ci, 16, absorbBuffer2, 0, 16);

                decT0.a = ((absorbBuffer1[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[0 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[0 * 4 + 3] & 0xff) << 24);
                decT0.b = ((absorbBuffer1[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[1 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[1 * 4 + 3] & 0xff) << 24);
                decT0.c = ((absorbBuffer1[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[2 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[2 * 4 + 3] & 0xff) << 24);
                decT0.d = ((absorbBuffer1[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer1[3 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer1[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer1[3 * 4 + 3] & 0xff) << 24);

                decT1.a = ((absorbBuffer2[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[0 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[0 * 4 + 3] & 0xff) << 24);
                decT1.b = ((absorbBuffer2[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[1 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[1 * 4 + 3] & 0xff) << 24);
                decT1.c = ((absorbBuffer2[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[2 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[2 * 4 + 3] & 0xff) << 24);
                decT1.d = ((absorbBuffer2[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer2[3 * 4 + 1] & 0xff) << 8)
                                | ((absorbBuffer2[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer2[3 * 4 + 3] & 0xff) << 24);

                // Calculate outputs without allocations
                decT0.xorInto(decZ0, decOut0);
                decT1.xorInto(decZ1, decOut1);

                // Update state
                this.update(decOut0, decOut1);

                // Convert to bytes without allocations
                decOut0.toBytes(encOutBuffer1);
                decOut1.toBytes(encOutBuffer2);

                // Create output array reusing the buffer
                System.arraycopy(encOutBuffer1, 0, decBuffer, 0, 16);
                System.arraycopy(encOutBuffer2, 0, decBuffer, 16, 16);

                return decBuffer;
        }

        // Reusable objects for decLast method
        private final AesBlock decLastZ0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decLastZ1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decLastT0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decLastT1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decLastV0 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decLastV1 = new AesBlock(0, 0, 0, 0);
        private final AesBlock decLastTmp = new AesBlock(0, 0, 0, 0);
        private final byte[] decLastPad = new byte[32];
        private final byte[] decLastOutBuffer1 = new byte[16];
        private final byte[] decLastOutBuffer2 = new byte[16];
        private final byte[] decLastBuffer = new byte[32];

        protected byte[] decLast(byte[] cn) {
                assert cn.length <= 32;
                var s = this.state;

                // Compute z0 = s[6] ⊕ s[1] ⊕ (s[2] & s[3]) without allocations
                s[2].andInto(s[3], decLastTmp);
                s[6].xorInto(s[1], decLastZ0);
                decLastTmp.xorInto(decLastZ0, decLastZ0);

                // Compute z1 = s[2] ⊕ s[5] ⊕ (s[6] & s[7]) without allocations
                s[6].andInto(s[7], decLastTmp);
                s[2].xorInto(s[5], decLastZ1);
                decLastTmp.xorInto(decLastZ1, decLastZ1);

                // Clear padding buffer and copy in ciphertext
                Arrays.fill(decLastPad, (byte) 0);
                System.arraycopy(cn, 0, decLastPad, 0, cn.length);

                // Load input blocks
                decLastT0.a = ((decLastPad[0 * 4 + 0] & 0xff) << 0) | ((decLastPad[0 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[0 * 4 + 2] & 0xff) << 16) | ((decLastPad[0 * 4 + 3] & 0xff) << 24);
                decLastT0.b = ((decLastPad[1 * 4 + 0] & 0xff) << 0) | ((decLastPad[1 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[1 * 4 + 2] & 0xff) << 16) | ((decLastPad[1 * 4 + 3] & 0xff) << 24);
                decLastT0.c = ((decLastPad[2 * 4 + 0] & 0xff) << 0) | ((decLastPad[2 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[2 * 4 + 2] & 0xff) << 16) | ((decLastPad[2 * 4 + 3] & 0xff) << 24);
                decLastT0.d = ((decLastPad[3 * 4 + 0] & 0xff) << 0) | ((decLastPad[3 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[3 * 4 + 2] & 0xff) << 16) | ((decLastPad[3 * 4 + 3] & 0xff) << 24);

                decLastT1.a = ((decLastPad[4 * 4 + 0] & 0xff) << 0) | ((decLastPad[4 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[4 * 4 + 2] & 0xff) << 16) | ((decLastPad[4 * 4 + 3] & 0xff) << 24);
                decLastT1.b = ((decLastPad[5 * 4 + 0] & 0xff) << 0) | ((decLastPad[5 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[5 * 4 + 2] & 0xff) << 16) | ((decLastPad[5 * 4 + 3] & 0xff) << 24);
                decLastT1.c = ((decLastPad[6 * 4 + 0] & 0xff) << 0) | ((decLastPad[6 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[6 * 4 + 2] & 0xff) << 16) | ((decLastPad[6 * 4 + 3] & 0xff) << 24);
                decLastT1.d = ((decLastPad[7 * 4 + 0] & 0xff) << 0) | ((decLastPad[7 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[7 * 4 + 2] & 0xff) << 16) | ((decLastPad[7 * 4 + 3] & 0xff) << 24);

                // XOR with keystream and convert to bytes
                decLastT0.xorInto(decLastZ0, decLastTmp);
                decLastTmp.toBytes(decLastOutBuffer1);

                decLastT1.xorInto(decLastZ1, decLastTmp);
                decLastTmp.toBytes(decLastOutBuffer2);

                // Create combined buffer
                System.arraycopy(decLastOutBuffer1, 0, decLastPad, 0, 16);
                System.arraycopy(decLastOutBuffer2, 0, decLastPad, 16, 16);

                // Copy out result of the right length
                var xn = new byte[cn.length];
                System.arraycopy(decLastPad, 0, xn, 0, cn.length);

                // Zero out parts after ciphertext length
                for (var i = cn.length; i < 32; i++) {
                        decLastPad[i] = 0;
                }

                // Load blocks for state update
                decLastV0.a = ((decLastPad[0 * 4 + 0] & 0xff) << 0) | ((decLastPad[0 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[0 * 4 + 2] & 0xff) << 16) | ((decLastPad[0 * 4 + 3] & 0xff) << 24);
                decLastV0.b = ((decLastPad[1 * 4 + 0] & 0xff) << 0) | ((decLastPad[1 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[1 * 4 + 2] & 0xff) << 16) | ((decLastPad[1 * 4 + 3] & 0xff) << 24);
                decLastV0.c = ((decLastPad[2 * 4 + 0] & 0xff) << 0) | ((decLastPad[2 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[2 * 4 + 2] & 0xff) << 16) | ((decLastPad[2 * 4 + 3] & 0xff) << 24);
                decLastV0.d = ((decLastPad[3 * 4 + 0] & 0xff) << 0) | ((decLastPad[3 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[3 * 4 + 2] & 0xff) << 16) | ((decLastPad[3 * 4 + 3] & 0xff) << 24);

                decLastV1.a = ((decLastPad[4 * 4 + 0] & 0xff) << 0) | ((decLastPad[4 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[4 * 4 + 2] & 0xff) << 16) | ((decLastPad[4 * 4 + 3] & 0xff) << 24);
                decLastV1.b = ((decLastPad[5 * 4 + 0] & 0xff) << 0) | ((decLastPad[5 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[5 * 4 + 2] & 0xff) << 16) | ((decLastPad[5 * 4 + 3] & 0xff) << 24);
                decLastV1.c = ((decLastPad[6 * 4 + 0] & 0xff) << 0) | ((decLastPad[6 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[6 * 4 + 2] & 0xff) << 16) | ((decLastPad[6 * 4 + 3] & 0xff) << 24);
                decLastV1.d = ((decLastPad[7 * 4 + 0] & 0xff) << 0) | ((decLastPad[7 * 4 + 1] & 0xff) << 8)
                                | ((decLastPad[7 * 4 + 2] & 0xff) << 16) | ((decLastPad[7 * 4 + 3] & 0xff) << 24);

                // Update state
                this.update(decLastV0, decLastV1);

                return xn;
        }

        // Reusable objects for mac method
        private final byte[] macLengthBytes = new byte[16];
        private final AesBlock macLengthBlock = new AesBlock(0, 0, 0, 0);
        private final AesBlock macT = new AesBlock(0, 0, 0, 0);
        private final AesBlock macResult = new AesBlock(0, 0, 0, 0);
        private final AesBlock macTmp = new AesBlock(0, 0, 0, 0);
        private final byte[] macTag16 = new byte[16];
        private final byte[] macTag32 = new byte[32];
        private final byte[] macT0Bytes = new byte[16];
        private final byte[] macT1Bytes = new byte[16];

        protected byte[] mac(final int ad_len_bytes, final int msg_len_bytes) {
                var s = this.state;

                // Encode lengths in bytes
                final long ad_len = (long) ad_len_bytes * 8;
                final long msg_len = (long) msg_len_bytes * 8;

                macLengthBytes[0 * 8 + 0] = (byte) (ad_len >> 0);
                macLengthBytes[0 * 8 + 1] = (byte) (ad_len >> 8);
                macLengthBytes[0 * 8 + 2] = (byte) (ad_len >> 16);
                macLengthBytes[0 * 8 + 3] = (byte) (ad_len >> 24);
                macLengthBytes[0 * 8 + 4] = (byte) (ad_len >> 32);
                macLengthBytes[0 * 8 + 5] = (byte) (ad_len >> 40);
                macLengthBytes[0 * 8 + 6] = (byte) (ad_len >> 48);
                macLengthBytes[0 * 8 + 7] = (byte) (ad_len >> 56);

                macLengthBytes[1 * 8 + 0] = (byte) (msg_len >> 0);
                macLengthBytes[1 * 8 + 1] = (byte) (msg_len >> 8);
                macLengthBytes[1 * 8 + 2] = (byte) (msg_len >> 16);
                macLengthBytes[1 * 8 + 3] = (byte) (msg_len >> 24);
                macLengthBytes[1 * 8 + 4] = (byte) (msg_len >> 32);
                macLengthBytes[1 * 8 + 5] = (byte) (msg_len >> 40);
                macLengthBytes[1 * 8 + 6] = (byte) (msg_len >> 48);
                macLengthBytes[1 * 8 + 7] = (byte) (msg_len >> 56);

                // Load length into block
                macLengthBlock.a = ((macLengthBytes[0 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[0 * 4 + 1] & 0xff) << 8)
                                | ((macLengthBytes[0 * 4 + 2] & 0xff) << 16)
                                | ((macLengthBytes[0 * 4 + 3] & 0xff) << 24);
                macLengthBlock.b = ((macLengthBytes[1 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[1 * 4 + 1] & 0xff) << 8)
                                | ((macLengthBytes[1 * 4 + 2] & 0xff) << 16)
                                | ((macLengthBytes[1 * 4 + 3] & 0xff) << 24);
                macLengthBlock.c = ((macLengthBytes[2 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[2 * 4 + 1] & 0xff) << 8)
                                | ((macLengthBytes[2 * 4 + 2] & 0xff) << 16)
                                | ((macLengthBytes[2 * 4 + 3] & 0xff) << 24);
                macLengthBlock.d = ((macLengthBytes[3 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[3 * 4 + 1] & 0xff) << 8)
                                | ((macLengthBytes[3 * 4 + 2] & 0xff) << 16)
                                | ((macLengthBytes[3 * 4 + 3] & 0xff) << 24);

                // XOR s[2] with length block
                s[2].xorInto(macLengthBlock, macT);

                // Run state updates
                for (var i = 0; i < 7; i++) {
                        this.update(macT, macT);
                }

                if (this.tag_length == 16) {
                        // Compute s[0] ⊕ s[1] ⊕ s[2] ⊕ s[3] ⊕ s[4] ⊕ s[5] ⊕ s[6] without allocations
                        s[0].xorInto(s[1], macResult);
                        s[2].xorInto(macResult, macResult);
                        s[3].xorInto(macResult, macResult);
                        s[4].xorInto(macResult, macResult);
                        s[5].xorInto(macResult, macResult);
                        s[6].xorInto(macResult, macResult);

                        // Convert to bytes without allocation
                        macResult.toBytes(macTag16);

                        this.state = null;
                        return macTag16;
                }

                assert this.tag_length == 32;

                // Compute s[0] ⊕ s[1] ⊕ s[2] ⊕ s[3] without allocations
                s[0].xorInto(s[1], macResult);
                s[2].xorInto(macResult, macResult);
                s[3].xorInto(macResult, macResult);
                macResult.toBytes(macT0Bytes);

                // Compute s[4] ⊕ s[5] ⊕ s[6] ⊕ s[7] without allocations
                s[4].xorInto(s[5], macTmp);
                s[6].xorInto(macTmp, macTmp);
                s[7].xorInto(macTmp, macTmp);
                macTmp.toBytes(macT1Bytes);

                // Combine results
                System.arraycopy(macT0Bytes, 0, macTag32, 0, 16);
                System.arraycopy(macT1Bytes, 0, macTag32, 16, 16);

                this.state = null;

                return macTag32;
        }
}