import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.github.cfrg.aegis.Aegis256;
import com.github.cfrg.aegis.VerificationFailedException;
import org.junit.jupiter.api.Test;

public class TestAegis256 {

  private static byte[] hexToBytes(String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length");
    }
    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < hex.length(); i += 2) {
      bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  @Test
  public void roundTripDetached() throws VerificationFailedException {
    final var key = Aegis256.keygen();
    final var nonce = Aegis256.noncegen();
    final var plaintext = "0123456789abcdef0123456789ABCDEF".getBytes();
    final var ad = "Additional data".getBytes();

    var aegis = new Aegis256(key, nonce, 16);
    final var ac = aegis.encryptDetached(plaintext, ad);

    aegis = new Aegis256(key, nonce, 16);
    var recovered_plaintext = aegis.decryptDetached(ac, ad);
    assertArrayEquals(plaintext, recovered_plaintext);
  }

  @Test
  public void roundTripAttached() throws VerificationFailedException {
    final var key = Aegis256.keygen();
    final var nonce = Aegis256.noncegen();
    final var plaintext = "0123456789abcdef0123456789ABCDE".getBytes();
    final var ad = "Additional data".getBytes();

    var aegis = new Aegis256(key, nonce, 16);
    var ciphertext = aegis.encrypt(plaintext, ad);

    aegis = new Aegis256(key, nonce, 16);
    var recovered_plaintext = aegis.decrypt(ciphertext, ad);
    assertArrayEquals(plaintext, recovered_plaintext);
  }

  @Test
  public void testVector1_128bit() throws VerificationFailedException {
    final var key = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    final var nonce =
        hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    final var plaintext = hexToBytes("00000000000000000000000000000000");
    final var ad = new byte[0];
    final var expectedCiphertext = hexToBytes("754fc3d8c973246dcc6d741412a4b236");
    final var expectedTag = hexToBytes("3fe91994768b332ed7f570a19ec5896e");

    var aegis = new Aegis256(key, nonce, 16);
    final var ac = aegis.encryptDetached(plaintext, ad);

    assertArrayEquals(expectedCiphertext, ac.ct);
    assertArrayEquals(expectedTag, ac.tag);
  }

  @Test
  public void testVector1_256bit() throws VerificationFailedException {
    final var key = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    final var nonce =
        hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    final var plaintext = hexToBytes("00000000000000000000000000000000");
    final var ad = new byte[0];
    final var expectedCiphertext = hexToBytes("754fc3d8c973246dcc6d741412a4b236");
    final var expectedTag =
        hexToBytes("1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13");

    var aegis = new Aegis256(key, nonce, 32);
    final var ac = aegis.encryptDetached(plaintext, ad);

    assertArrayEquals(expectedCiphertext, ac.ct);
    assertArrayEquals(expectedTag, ac.tag);
  }

  @Test
  public void testVector2_128bit() throws VerificationFailedException {
    final var key = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    final var nonce =
        hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    final var plaintext = new byte[0];
    final var ad = new byte[0];
    final var expectedCiphertext = new byte[0];
    final var expectedTag = hexToBytes("e3def978a0f054afd1e761d7553afba3");

    var aegis = new Aegis256(key, nonce, 16);
    final var ac = aegis.encryptDetached(plaintext, ad);

    assertArrayEquals(expectedCiphertext, ac.ct);
    assertArrayEquals(expectedTag, ac.tag);
  }

  @Test
  public void testVector2_256bit() throws VerificationFailedException {
    final var key = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    final var nonce =
        hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    final var plaintext = new byte[0];
    final var ad = new byte[0];
    final var expectedCiphertext = new byte[0];
    final var expectedTag =
        hexToBytes("6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a");

    var aegis = new Aegis256(key, nonce, 32);
    final var ac = aegis.encryptDetached(plaintext, ad);

    assertArrayEquals(expectedCiphertext, ac.ct);
    assertArrayEquals(expectedTag, ac.tag);
  }

  @Test
  public void testVector3_128bit() throws VerificationFailedException {
    final var key = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    final var nonce =
        hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    final var plaintext =
        hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    final var ad = hexToBytes("0001020304050607");
    final var expectedCiphertext =
        hexToBytes("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711");
    final var expectedTag = hexToBytes("8d86f91ee606e9ff26a01b64ccbdd91d");

    var aegis = new Aegis256(key, nonce, 16);
    final var ac = aegis.encryptDetached(plaintext, ad);

    assertArrayEquals(expectedCiphertext, ac.ct);
    assertArrayEquals(expectedTag, ac.tag);
  }

  @Test
  public void testVector3_256bit() throws VerificationFailedException {
    final var key = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    final var nonce =
        hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    final var plaintext =
        hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    final var ad = hexToBytes("0001020304050607");
    final var expectedCiphertext =
        hexToBytes("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711");
    final var expectedTag =
        hexToBytes("b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a");

    var aegis = new Aegis256(key, nonce, 32);
    final var ac = aegis.encryptDetached(plaintext, ad);

    assertArrayEquals(expectedCiphertext, ac.ct);
    assertArrayEquals(expectedTag, ac.tag);
  }
}
