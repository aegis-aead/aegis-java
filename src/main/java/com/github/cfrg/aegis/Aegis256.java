package com.github.cfrg.aegis;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Aegis256 is a class that implements the AEGIS-256 authenticated encryption
 * algorithm.
 */
public class Aegis256 {
    /**
     * Generates a random 256-bit key using a secure random number generator.
     *
     * @return the generated key as a byte array
     */
    public static byte[] keygen() {
        var key = new byte[32];
        var rng = new SecureRandom();
        rng.nextBytes(key);
        return key;
    }

    /**
     * Generates a random 256-bit nonce using a secure random number generator.
     *
     * @return the generated nonce as a byte array
     */
    public static byte[] noncegen() {
        var nonce = new byte[32];
        var rng = new SecureRandom();
        rng.nextBytes(nonce);
        return nonce;
    }

    AesBlock[] state = new AesBlock[6];

    int tag_length;

    public Aegis256(final byte[] key, final byte[] nonce, final int tag_length) throws InvalidParameterException {
        if (tag_length != 16 && tag_length != 32) {
            throw new InvalidParameterException("invalid tag length");
        }
        if (key.length != 32) {
            throw new InvalidParameterException("invalid key length");
        }
        if (nonce.length != 32) {
            throw new InvalidParameterException("invalid nonce length");
        }
        this.tag_length = tag_length;

        final byte[] c0_bytes = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90 - 256,
                0xe9 - 256, 0x79, 0x62 };
        final byte[] c1_bytes = { 0xdb - 256, 0x3d, 0x18, 0x55, 0x6d, 0xc2 - 256, 0x2f, 0xf1 - 256, 0x20, 0x11, 0x31,
                0x42, 0x73, 0xb5 - 256, 0x28, 0xdd - 256 };
        final AesBlock c0 = new AesBlock(c0_bytes);
        final AesBlock c1 = new AesBlock(c1_bytes);

        final AesBlock k0 = new AesBlock(Arrays.copyOfRange(key, 0, 16));
        final AesBlock k1 = new AesBlock(Arrays.copyOfRange(key, 16, 32));
        final AesBlock n0 = new AesBlock(Arrays.copyOfRange(nonce, 0, 16));
        final AesBlock n1 = new AesBlock(Arrays.copyOfRange(nonce, 16, 32));
        final AesBlock k0n0 = k0.xor(n0);
        final AesBlock k1n1 = k1.xor(n1);
        var s = this.state;
        s[0] = k0n0;
        s[1] = k1n1;
        s[2] = new AesBlock(c1);
        s[3] = new AesBlock(c0);
        s[4] = k0.xor(c0);
        s[5] = k1.xor(c1);
        for (int i = 0; i < 4; i++) {
            this.update(k0);
            this.update(k1);
            this.update(k0n0);
            this.update(k1n1);
        }
    }

    public AuthenticatedCiphertext encryptDetached(final byte[] msg, final byte[] ad) {
        var ciphertext = new byte[msg.length];
        var i = 0;
        if (ad != null) {
            for (; i + 16 <= ad.length; i += 16) {
                this.absorb(Arrays.copyOfRange(ad, i, i + 16));
            }
            if (ad.length % 16 != 0) {
                var pad = new byte[16];
                Arrays.fill(pad, (byte) 0);
                for (var j = 0; j < ad.length % 16; j++) {
                    pad[j] = ad[i + j];
                }
                this.absorb(pad);
            }
        }
        if (msg != null) {
            i = 0;
            for (; i + 16 <= msg.length; i += 16) {
                var ci = this.enc(Arrays.copyOfRange(msg, i, i + 16));
                for (var j = 0; j < 16; j++) {
                    ciphertext[i + j] = ci[j];
                }
            }
            if (msg.length % 16 != 0) {
                var pad = new byte[16];
                Arrays.fill(pad, (byte) 0);
                for (var j = 0; j < msg.length % 16; j++) {
                    pad[j] = msg[i + j];
                }
                var ci = this.enc(pad);
                for (var j = 0; j < msg.length % 16; j++) {
                    ciphertext[i + j] = ci[j];
                }
            }
        }
        final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);

        return new AuthenticatedCiphertext(ciphertext, tag);
    }

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

    public byte[] decryptDetached(final AuthenticatedCiphertext ac, final byte[] ad)
            throws VerificationFailedException {
        var i = 0;
        if (ad != null) {
            for (; i + 16 <= ad.length; i += 16) {
                this.absorb(Arrays.copyOfRange(ad, i, i + 16));
            }
            if (ad.length % 16 != 0) {
                var pad = new byte[16];
                Arrays.fill(pad, (byte) 0);
                for (var j = 0; j < ad.length % 16; j++) {
                    pad[j] = ad[i + j];
                }
                this.absorb(pad);
            }
        }
        var msg = new byte[ac.ct.length];
        i = 0;
        for (; i + 16 <= ac.ct.length; i += 16) {
            var xi = this.dec(Arrays.copyOfRange(ac.ct, i, i + 16));
            for (var j = 0; j < 16; j++) {
                msg[i + j] = xi[j];
            }
        }
        if (ac.ct.length % 16 != 0) {
            var xi = this.decLast(Arrays.copyOfRange(ac.ct, i, ac.ct.length));
            for (var j = 0; j < ac.ct.length % 16; j++) {
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
        return "Aegis256 [state=" + Arrays.toString(state) + ", tag_length=" + tag_length + "]";
    }

    // Reusable temporary block to avoid allocations in update method
    private final AesBlock tmpBlock = new AesBlock(0, 0, 0, 0);

    protected void update(final AesBlock m) {
        var s = this.state;

        // Save s[5] to temporary block
        tmpBlock.a = s[5].a;
        tmpBlock.b = s[5].b;
        tmpBlock.c = s[5].c;
        tmpBlock.d = s[5].d;

        // Perform state update using non-allocating methods
        s[4].encryptInto(s[5], s[5]);
        s[3].encryptInto(s[4], s[4]);
        s[2].encryptInto(s[3], s[3]);
        s[1].encryptInto(s[2], s[2]);
        s[0].encryptInto(s[1], s[1]);
        tmpBlock.encryptInto(s[0], s[0]);

        // Apply message mixing
        m.xorInto(s[0], s[0]);
    }

    // Reusable objects for absorb method
    private final byte[] absorbBuffer = new byte[16];
    private final AesBlock absorbBlock = new AesBlock(0, 0, 0, 0);

    protected void absorb(byte[] ai) {
        assert ai.length == 16;

        // Copy data into reusable buffer
        System.arraycopy(ai, 0, absorbBuffer, 0, 16);

        // Load data into reusable AesBlock object
        absorbBlock.a = ((absorbBuffer[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[0 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[0 * 4 + 3] & 0xff) << 24);
        absorbBlock.b = ((absorbBuffer[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[1 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[1 * 4 + 3] & 0xff) << 24);
        absorbBlock.c = ((absorbBuffer[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[2 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[2 * 4 + 3] & 0xff) << 24);
        absorbBlock.d = ((absorbBuffer[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[3 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[3 * 4 + 3] & 0xff) << 24);

        this.update(absorbBlock);
    }

    // Reusable objects for enc method
    private final AesBlock encZ = new AesBlock(0, 0, 0, 0);
    private final AesBlock encT = new AesBlock(0, 0, 0, 0);
    private final AesBlock encTmp = new AesBlock(0, 0, 0, 0);
    private final byte[] encBuffer = new byte[16];

    protected byte[] enc(byte[] xi) {
        assert xi.length == 16;
        var s = this.state;

        // Compute z = s[1] ⊕ s[4] ⊕ s[5] ⊕ (s[2] & s[3]) without allocations
        s[2].andInto(s[3], encTmp);
        s[1].xorInto(s[4], encZ);
        s[5].xorInto(encZ, encZ);
        encTmp.xorInto(encZ, encZ);

        // Load input into t without array copying
        System.arraycopy(xi, 0, absorbBuffer, 0, 16);

        encT.a = ((absorbBuffer[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[0 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[0 * 4 + 3] & 0xff) << 24);
        encT.b = ((absorbBuffer[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[1 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[1 * 4 + 3] & 0xff) << 24);
        encT.c = ((absorbBuffer[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[2 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[2 * 4 + 3] & 0xff) << 24);
        encT.d = ((absorbBuffer[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[3 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[3 * 4 + 3] & 0xff) << 24);

        // XOR and convert to bytes without allocations
        encT.xorInto(encZ, encTmp);
        encTmp.toBytes(encBuffer);

        // Update state
        this.update(encT);

        return encBuffer;
    }

    // Reusable objects for dec method
    private final AesBlock decZ = new AesBlock(0, 0, 0, 0);
    private final AesBlock decT = new AesBlock(0, 0, 0, 0);
    private final AesBlock decOut = new AesBlock(0, 0, 0, 0);
    private final AesBlock decTmp = new AesBlock(0, 0, 0, 0);
    private final byte[] decBuffer = new byte[16];

    protected byte[] dec(byte[] ci) {
        assert ci.length == 16;
        var s = this.state;

        // Compute z = s[1] ⊕ s[4] ⊕ s[5] ⊕ (s[2] & s[3]) without allocations
        s[2].andInto(s[3], decTmp);
        s[1].xorInto(s[4], decZ);
        s[5].xorInto(decZ, decZ);
        decTmp.xorInto(decZ, decZ);

        // Load input without array copying
        System.arraycopy(ci, 0, absorbBuffer, 0, 16);

        decT.a = ((absorbBuffer[0 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[0 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[0 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[0 * 4 + 3] & 0xff) << 24);
        decT.b = ((absorbBuffer[1 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[1 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[1 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[1 * 4 + 3] & 0xff) << 24);
        decT.c = ((absorbBuffer[2 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[2 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[2 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[2 * 4 + 3] & 0xff) << 24);
        decT.d = ((absorbBuffer[3 * 4 + 0] & 0xff) << 0) | ((absorbBuffer[3 * 4 + 1] & 0xff) << 8)
                | ((absorbBuffer[3 * 4 + 2] & 0xff) << 16) | ((absorbBuffer[3 * 4 + 3] & 0xff) << 24);

        // XOR to get plaintext
        decT.xorInto(decZ, decOut);

        // Update state
        this.update(decOut);

        // Convert to bytes without allocation
        decOut.toBytes(decBuffer);

        return decBuffer;
    }

    // Reusable objects for decLast method
    private final AesBlock decLastZ = new AesBlock(0, 0, 0, 0);
    private final AesBlock decLastT = new AesBlock(0, 0, 0, 0);
    private final AesBlock decLastV = new AesBlock(0, 0, 0, 0);
    private final AesBlock decLastTmp = new AesBlock(0, 0, 0, 0);
    private final byte[] decLastPad = new byte[16];
    private final byte[] decLastOutBytes = new byte[16];

    protected byte[] decLast(byte cn[]) {
        assert cn.length <= 16;
        var s = this.state;

        // Compute z = s[1] ⊕ s[4] ⊕ s[5] ⊕ (s[2] & s[3]) without allocations
        s[2].andInto(s[3], decLastTmp);
        s[1].xorInto(s[4], decLastZ);
        s[5].xorInto(decLastZ, decLastZ);
        decLastTmp.xorInto(decLastZ, decLastZ);

        // Clear padding buffer and copy in ciphertext
        Arrays.fill(decLastPad, (byte) 0);
        System.arraycopy(cn, 0, decLastPad, 0, cn.length);

        // Load block for decryption
        decLastT.a = ((decLastPad[0 * 4 + 0] & 0xff) << 0) | ((decLastPad[0 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[0 * 4 + 2] & 0xff) << 16) | ((decLastPad[0 * 4 + 3] & 0xff) << 24);
        decLastT.b = ((decLastPad[1 * 4 + 0] & 0xff) << 0) | ((decLastPad[1 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[1 * 4 + 2] & 0xff) << 16) | ((decLastPad[1 * 4 + 3] & 0xff) << 24);
        decLastT.c = ((decLastPad[2 * 4 + 0] & 0xff) << 0) | ((decLastPad[2 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[2 * 4 + 2] & 0xff) << 16) | ((decLastPad[2 * 4 + 3] & 0xff) << 24);
        decLastT.d = ((decLastPad[3 * 4 + 0] & 0xff) << 0) | ((decLastPad[3 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[3 * 4 + 2] & 0xff) << 16) | ((decLastPad[3 * 4 + 3] & 0xff) << 24);

        // XOR with keystream and convert to bytes
        decLastT.xorInto(decLastZ, decLastTmp);
        decLastTmp.toBytes(decLastOutBytes);

        // Copy bytes to padding buffer
        System.arraycopy(decLastOutBytes, 0, decLastPad, 0, 16);

        // Extract plaintext of the right length
        var xn = new byte[cn.length];
        System.arraycopy(decLastPad, 0, xn, 0, cn.length);

        // Zero out parts after ciphertext length
        for (var i = cn.length; i < 16; i++) {
            decLastPad[i] = 0;
        }

        // Load block for state update
        decLastV.a = ((decLastPad[0 * 4 + 0] & 0xff) << 0) | ((decLastPad[0 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[0 * 4 + 2] & 0xff) << 16) | ((decLastPad[0 * 4 + 3] & 0xff) << 24);
        decLastV.b = ((decLastPad[1 * 4 + 0] & 0xff) << 0) | ((decLastPad[1 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[1 * 4 + 2] & 0xff) << 16) | ((decLastPad[1 * 4 + 3] & 0xff) << 24);
        decLastV.c = ((decLastPad[2 * 4 + 0] & 0xff) << 0) | ((decLastPad[2 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[2 * 4 + 2] & 0xff) << 16) | ((decLastPad[2 * 4 + 3] & 0xff) << 24);
        decLastV.d = ((decLastPad[3 * 4 + 0] & 0xff) << 0) | ((decLastPad[3 * 4 + 1] & 0xff) << 8)
                | ((decLastPad[3 * 4 + 2] & 0xff) << 16) | ((decLastPad[3 * 4 + 3] & 0xff) << 24);

        // Update state
        this.update(decLastV);

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
                | ((macLengthBytes[0 * 4 + 2] & 0xff) << 16) | ((macLengthBytes[0 * 4 + 3] & 0xff) << 24);
        macLengthBlock.b = ((macLengthBytes[1 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[1 * 4 + 1] & 0xff) << 8)
                | ((macLengthBytes[1 * 4 + 2] & 0xff) << 16) | ((macLengthBytes[1 * 4 + 3] & 0xff) << 24);
        macLengthBlock.c = ((macLengthBytes[2 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[2 * 4 + 1] & 0xff) << 8)
                | ((macLengthBytes[2 * 4 + 2] & 0xff) << 16) | ((macLengthBytes[2 * 4 + 3] & 0xff) << 24);
        macLengthBlock.d = ((macLengthBytes[3 * 4 + 0] & 0xff) << 0) | ((macLengthBytes[3 * 4 + 1] & 0xff) << 8)
                | ((macLengthBytes[3 * 4 + 2] & 0xff) << 16) | ((macLengthBytes[3 * 4 + 3] & 0xff) << 24);

        // XOR s[3] with length block
        s[3].xorInto(macLengthBlock, macT);

        // Run state updates
        for (var i = 0; i < 7; i++) {
            this.update(macT);
        }

        if (this.tag_length == 16) {
            // Compute s[0] ⊕ s[1] ⊕ s[2] ⊕ s[3] ⊕ s[4] ⊕ s[5] without allocations
            s[0].xorInto(s[1], macResult);
            s[2].xorInto(macResult, macResult);
            s[3].xorInto(macResult, macResult);
            s[4].xorInto(macResult, macResult);
            s[5].xorInto(macResult, macResult);

            // Convert to bytes without allocation
            macResult.toBytes(macTag16);

            this.state = null;
            return macTag16;
        }

        assert this.tag_length == 32;

        // Compute s[0] ⊕ s[1] ⊕ s[2] without allocations
        s[0].xorInto(s[1], macResult);
        s[2].xorInto(macResult, macResult);
        macResult.toBytes(macT0Bytes);

        // Compute s[3] ⊕ s[4] ⊕ s[5] without allocations
        s[3].xorInto(s[4], macTmp);
        s[5].xorInto(macTmp, macTmp);
        macTmp.toBytes(macT1Bytes);

        // Combine results
        System.arraycopy(macT0Bytes, 0, macTag32, 0, 16);
        System.arraycopy(macT1Bytes, 0, macTag32, 16, 16);

        this.state = null;

        return macTag32;
    }
}