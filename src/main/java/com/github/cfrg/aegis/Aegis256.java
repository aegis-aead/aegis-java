package com.github.cfrg.aegis;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/** Aegis256 is a class that implements the AEGIS-256 authenticated encryption algorithm. */
public class Aegis256 {

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

  private final byte[] tempBuffer = new byte[16];
  private final AesBlock tempBlock = new AesBlock(0, 0, 0, 0);

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

  public Aegis256(final byte[] key, final byte[] nonce, final int tag_length)
      throws InvalidParameterException {
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

    final AesBlock k0 = new AesBlock(Arrays.copyOfRange(key, 0, 16));
    final AesBlock k1 = new AesBlock(Arrays.copyOfRange(key, 16, 32));
    final AesBlock n0 = new AesBlock(Arrays.copyOfRange(nonce, 0, 16));
    final AesBlock n1 = new AesBlock(Arrays.copyOfRange(nonce, 16, 32));
    final AesBlock k0n0 = k0.xor(n0);
    final AesBlock k1n1 = k1.xor(n1);
    var s = this.state;
    s[0] = k0n0;
    s[1] = k1n1;
    s[2] = new AesBlock(C1);
    s[3] = new AesBlock(C0);
    s[4] = k0.xor(C0);
    s[5] = k1.xor(C1);
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
        Arrays.fill(tempBuffer, (byte) 0);
        var remaining = ad.length % 16;
        System.arraycopy(ad, i, tempBuffer, 0, remaining);
        this.absorb(tempBuffer);
      }
    }
    if (msg != null) {
      i = 0;
      for (; i + 16 <= msg.length; i += 16) {
        var ci = this.enc(Arrays.copyOfRange(msg, i, i + 16));
        System.arraycopy(ci, 0, ciphertext, i, 16);
      }
      if (msg.length % 16 != 0) {
        Arrays.fill(tempBuffer, (byte) 0);
        var remaining = msg.length % 16;
        System.arraycopy(msg, i, tempBuffer, 0, remaining);
        var ci = this.enc(tempBuffer);
        System.arraycopy(ci, 0, ciphertext, i, remaining);
      }
    }
    final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);

    return new AuthenticatedCiphertext(ciphertext, tag);
  }

  public byte[] encrypt(final byte[] msg, final byte[] ad) {
    var res = this.encryptDetached(msg, ad);
    var ciphertext = new byte[res.ct.length + res.tag.length];
    System.arraycopy(res.ct, 0, ciphertext, 0, res.ct.length);
    System.arraycopy(res.tag, 0, ciphertext, res.ct.length, res.tag.length);
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
        Arrays.fill(tempBuffer, (byte) 0);
        var remaining = ad.length % 16;
        System.arraycopy(ad, i, tempBuffer, 0, remaining);
        this.absorb(tempBuffer);
      }
    }
    var msg = new byte[ac.ct.length];
    i = 0;
    for (; i + 16 <= ac.ct.length; i += 16) {
      var xi = this.dec(Arrays.copyOfRange(ac.ct, i, i + 16));
      System.arraycopy(xi, 0, msg, i, 16);
    }
    if (ac.ct.length % 16 != 0) {
      var xi = this.decLast(Arrays.copyOfRange(ac.ct, i, ac.ct.length));
      System.arraycopy(xi, 0, msg, i, ac.ct.length % 16);
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
    return "Aegis256 [state=" + Arrays.toString(state) + ", tag_length=" + tag_length + "]";
  }

  protected void update(final AesBlock m) {
    var s = this.state;
    final var tmp = new AesBlock(s[5]);
    s[5] = s[4].encrypt(s[5]);
    s[4] = s[3].encrypt(s[4]);
    s[3] = s[2].encrypt(s[3]);
    s[2] = s[1].encrypt(s[2]);
    s[1] = s[0].encrypt(s[1]);
    s[0] = tmp.encrypt(s[0]);

    s[0] = s[0].xor(m);
  }

  protected void absorb(byte[] ai) {
    assert ai.length == 16;
    final var t = new AesBlock(ai);
    this.update(t);
  }

  protected byte[] enc(byte[] xi) {
    assert xi.length == 16;
    var s = this.state;
    final var z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]));
    final var t = new AesBlock(xi);
    final var ci = t.xor(z).toBytes();
    this.update(t);
    return ci;
  }

  protected byte[] dec(byte[] ci) {
    assert ci.length == 16;
    var s = this.state;
    final var z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]));
    final var t = new AesBlock(ci);
    final var out = t.xor(z);
    this.update(out);
    return out.toBytes();
  }

  protected byte[] decLast(byte cn[]) {
    assert cn.length <= 16;
    var s = this.state;
    final var z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]));
    Arrays.fill(tempBuffer, (byte) 0);
    System.arraycopy(cn, 0, tempBuffer, 0, cn.length);
    final var t = new AesBlock(tempBuffer);
    final var out_bytes = t.xor(z).toBytes();
    System.arraycopy(out_bytes, 0, tempBuffer, 0, 16);
    var xn = new byte[cn.length];
    System.arraycopy(tempBuffer, 0, xn, 0, cn.length);
    for (var i = cn.length; i < 16; i++) {
      tempBuffer[i] = 0;
    }
    final var v = new AesBlock(tempBuffer);
    this.update(v);

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

    final var t = s[3].xor(new AesBlock(bytes));
    for (var i = 0; i < 7; i++) {
      this.update(t);
    }

    if (this.tag_length == 16) {
      return s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).toBytes();
    }
    assert this.tag_length == 32;
    var tag = new byte[32];
    final var t0 = s[0].xor(s[1]).xor(s[2]).toBytes();
    final var t1 = s[3].xor(s[4]).xor(s[5]).toBytes();
    System.arraycopy(t0, 0, tag, 0, 16);
    System.arraycopy(t1, 0, tag, 16, 16);

    this.state = null;

    return tag;
  }
}
