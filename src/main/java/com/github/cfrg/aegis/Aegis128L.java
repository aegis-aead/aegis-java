package com.github.cfrg.aegis;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/** Aegis128L is a class that implements the AEGIS-128L authenticated encryption algorithm. */
public class Aegis128L {

  private static final byte[] C0_BYTES = {
    0x00,
    0x01,
    0x01,
    0x02,
    0x03,
    0x05,
    0x08,
    0x0d,
    0x15,
    0x22,
    0x37,
    0x59,
    (byte) 0x90,
    (byte) 0xe9,
    0x79,
    0x62
  };

  private static final byte[] C1_BYTES = {
    (byte) 0xdb,
    0x3d,
    0x18,
    0x55,
    0x6d,
    (byte) 0xc2,
    0x2f,
    (byte) 0xf1,
    0x20,
    0x11,
    0x31,
    0x42,
    0x73,
    (byte) 0xb5,
    0x28,
    (byte) 0xdd
  };

  private static final AesBlock C0 = new AesBlock(C0_BYTES);
  private static final AesBlock C1 = new AesBlock(C1_BYTES);

  private final byte[] tempBuffer = new byte[32];

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

  public Aegis128L(final byte[] key, final byte[] nonce, final int tag_length)
      throws InvalidParameterException {
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

    final AesBlock key_block = new AesBlock(key);
    final AesBlock nonce_block = new AesBlock(nonce);
    var s = this.state;
    s[0] = key_block.xor(nonce_block);
    s[1] = new AesBlock(C1);
    s[2] = new AesBlock(C0);
    s[3] = new AesBlock(C1);
    s[4] = key_block.xor(nonce_block);
    s[5] = key_block.xor(C0);
    s[6] = key_block.xor(C1);
    s[7] = key_block.xor(C0);

    for (int i = 0; i < 10; i++) {
      this.update(nonce_block, key_block);
    }
  }

  /**
   * Encrypts a message with associated data.
   *
   * @param msg the message to encrypt
   * @param ad the associated data
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
        Arrays.fill(tempBuffer, (byte) 0);
        var remaining = ad.length % 32;
        System.arraycopy(ad, i, tempBuffer, 0, remaining);
        this.absorb(tempBuffer);
      }
    }
    if (msg != null) {
      i = 0;
      for (; i + 32 <= msg.length; i += 32) {
        var ci = this.enc(Arrays.copyOfRange(msg, i, i + 32));
        System.arraycopy(ci, 0, ciphertext, i, 32);
      }
      if (msg.length % 32 != 0) {
        Arrays.fill(tempBuffer, (byte) 0);
        var remaining = msg.length % 32;
        System.arraycopy(msg, i, tempBuffer, 0, remaining);
        var ci = this.enc(tempBuffer);
        System.arraycopy(ci, 0, ciphertext, i, remaining);
      }
    }
    final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);

    return new AuthenticatedCiphertext(ciphertext, tag);
  }

  /**
   * Encrypts a message with associated data.
   *
   * @param msg the message to encrypt
   * @param ad the associated data
   * @return the authenticated ciphertext that includes the tag
   */
  public byte[] encrypt(final byte[] msg, final byte[] ad) {
    var res = this.encryptDetached(msg, ad);
    var ciphertext = new byte[res.ct.length + res.tag.length];
    System.arraycopy(res.ct, 0, ciphertext, 0, res.ct.length);
    System.arraycopy(res.tag, 0, ciphertext, res.ct.length, res.tag.length);
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
        Arrays.fill(tempBuffer, (byte) 0);
        var remaining = ad.length % 32;
        System.arraycopy(ad, i, tempBuffer, 0, remaining);
        this.absorb(tempBuffer);
      }
    }
    var msg = new byte[ac.ct.length];
    i = 0;
    for (; i + 32 <= ac.ct.length; i += 32) {
      var xi = this.dec(Arrays.copyOfRange(ac.ct, i, i + 32));
      System.arraycopy(xi, 0, msg, i, 32);
    }
    if (ac.ct.length % 32 != 0) {
      var xi = this.decLast(Arrays.copyOfRange(ac.ct, i, ac.ct.length));
      System.arraycopy(xi, 0, msg, i, ac.ct.length % 32);
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
   * @param ad The associated data used for decryption.
   * @return The decrypted plaintext.
   * @throws VerificationFailedException If the ciphertext is truncated or decryption fails.
   */
  public byte[] decrypt(final byte[] ciphertext, final byte[] ad)
      throws VerificationFailedException {
    if (ciphertext.length < this.tag_length) {
      throw new VerificationFailedException("truncated ciphertext");
    }
    var ct = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - this.tag_length);
    var tag =
        Arrays.copyOfRange(ciphertext, ciphertext.length - this.tag_length, ciphertext.length);
    return this.decryptDetached(new AuthenticatedCiphertext(ct, tag), ad);
  }

  @Override
  public String toString() {
    return "Aegis128L [state=" + Arrays.toString(state) + ", tag_length=" + tag_length + "]";
  }

  protected void update(final AesBlock m0, final AesBlock m1) {
    var s = this.state;
    final var tmp = new AesBlock(s[7]);
    s[7] = s[6].encrypt(s[7]);
    s[6] = s[5].encrypt(s[6]);
    s[5] = s[4].encrypt(s[5]);
    s[4] = s[3].encrypt(s[4]);
    s[3] = s[2].encrypt(s[3]);
    s[2] = s[1].encrypt(s[2]);
    s[1] = s[0].encrypt(s[1]);
    s[0] = tmp.encrypt(s[0]);

    s[4] = s[4].xor(m1);
    s[0] = s[0].xor(m0);
  }

  protected void absorb(byte[] ai) {
    assert ai.length == 32;
    final var t0 = new AesBlock(Arrays.copyOfRange(ai, 0, 16));
    final var t1 = new AesBlock(Arrays.copyOfRange(ai, 16, 32));
    this.update(t0, t1);
  }

  protected byte[] enc(byte[] xi) {
    assert xi.length == 32;
    var s = this.state;
    final var z0 = s[6].xor(s[1]).xor(s[2].and(s[3]));
    final var z1 = s[2].xor(s[5]).xor(s[6].and(s[7]));
    final var t0 = new AesBlock(Arrays.copyOfRange(xi, 0, 16));
    final var t1 = new AesBlock(Arrays.copyOfRange(xi, 16, 32));
    final var out0_bytes = t0.xor(z0).toBytes();
    final var out1_bytes = t1.xor(z1).toBytes();
    this.update(t0, t1);
    var ci = new byte[32];
    System.arraycopy(out0_bytes, 0, ci, 0, 16);
    System.arraycopy(out1_bytes, 0, ci, 16, 16);
    return ci;
  }

  protected byte[] dec(byte[] ci) {
    assert ci.length == 32;
    var s = this.state;
    final var z0 = s[6].xor(s[1]).xor(s[2].and(s[3]));
    final var z1 = s[2].xor(s[5]).xor(s[6].and(s[7]));
    final var t0 = new AesBlock(Arrays.copyOfRange(ci, 0, 16));
    final var t1 = new AesBlock(Arrays.copyOfRange(ci, 16, 32));
    final var out0 = t0.xor(z0);
    final var out1 = t1.xor(z1);
    this.update(out0, out1);
    final var out0_bytes = out0.toBytes();
    final var out1_bytes = out1.toBytes();
    var xi = new byte[32];
    System.arraycopy(out0_bytes, 0, xi, 0, 16);
    System.arraycopy(out1_bytes, 0, xi, 16, 16);
    return xi;
  }

  protected byte[] decLast(byte[] cn) {
    assert cn.length <= 32;
    var s = this.state;
    final var z0 = s[6].xor(s[1]).xor(s[2].and(s[3]));
    final var z1 = s[2].xor(s[5]).xor(s[6].and(s[7]));
    var pad = new byte[32];
    Arrays.fill(pad, (byte) 0);
    for (var i = 0; i < cn.length; i++) {
      pad[i] = cn[i];
    }
    final var t0 = new AesBlock(Arrays.copyOfRange(pad, 0, 16));
    final var t1 = new AesBlock(Arrays.copyOfRange(pad, 16, 32));
    final var out0_bytes = t0.xor(z0).toBytes();
    final var out1_bytes = t1.xor(z1).toBytes();
    System.arraycopy(out0_bytes, 0, pad, 0, 16);
    System.arraycopy(out1_bytes, 0, pad, 16, 16);
    var xn = new byte[cn.length];
    for (var i = 0; i < cn.length; i++) {
      xn[i] = pad[i];
    }
    for (var i = cn.length; i < 32; i++) {
      pad[i] = 0;
    }
    final var v0 = new AesBlock(Arrays.copyOfRange(pad, 0, 16));
    final var v1 = new AesBlock(Arrays.copyOfRange(pad, 16, 32));
    this.update(v0, v1);

    return xn;
  }

  protected byte[] mac(final int ad_len_bytes, final int msg_len_bytes) {
    var s = this.state;
    var bytes = new byte[16];

    final long ad_len = (long) ad_len_bytes * 8;
    final long msg_len = (long) msg_len_bytes * 8;

    bytes[0 * 8 + 0] = (byte) (ad_len >> 0);
    bytes[0 * 8 + 1] = (byte) (ad_len >> 8);
    bytes[0 * 8 + 2] = (byte) (ad_len >> 16);
    bytes[0 * 8 + 3] = (byte) (ad_len >> 24);
    bytes[0 * 8 + 4] = (byte) (ad_len >> 32);
    bytes[0 * 8 + 5] = (byte) (ad_len >> 40);
    bytes[0 * 8 + 6] = (byte) (ad_len >> 48);
    bytes[0 * 8 + 7] = (byte) (ad_len >> 56);

    bytes[1 * 8 + 0] = (byte) (msg_len >> 0);
    bytes[1 * 8 + 1] = (byte) (msg_len >> 8);
    bytes[1 * 8 + 2] = (byte) (msg_len >> 16);
    bytes[1 * 8 + 3] = (byte) (msg_len >> 24);
    bytes[1 * 8 + 4] = (byte) (msg_len >> 32);
    bytes[1 * 8 + 5] = (byte) (msg_len >> 40);
    bytes[1 * 8 + 6] = (byte) (msg_len >> 48);
    bytes[1 * 8 + 7] = (byte) (msg_len >> 56);

    final var t = s[2].xor(new AesBlock(bytes));
    for (var i = 0; i < 7; i++) {
      this.update(t, t);
    }

    if (this.tag_length == 16) {
      return s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).xor(s[6]).toBytes();
    }
    assert this.tag_length == 32;
    var tag = new byte[32];
    final var t0 = s[0].xor(s[1]).xor(s[2]).xor(s[3]).toBytes();
    final var t1 = s[4].xor(s[5]).xor(s[6]).xor(s[7]).toBytes();
    System.arraycopy(t0, 0, tag, 0, 16);
    System.arraycopy(t1, 0, tag, 16, 16);

    this.state = null;

    return tag;
  }
}
