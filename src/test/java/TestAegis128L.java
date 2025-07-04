
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.github.cfrg.aegis.Aegis128L;
import com.github.cfrg.aegis.VerificationFailedException;

public class TestAegis128L {

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
        final var key = Aegis128L.keygen();
        final var nonce = Aegis128L.noncegen();
        final var plaintext = "0123456789abcdef0123456789ABCDEF".getBytes();
        final var ad = "Additional data".getBytes();

        var aegis = new Aegis128L(key, nonce, 16);
        final var ac = aegis.encryptDetached(plaintext, ad);

        aegis = new Aegis128L(key, nonce, 16);
        var recovered_plaintext = aegis.decryptDetached(ac, ad);
        assertArrayEquals(plaintext, recovered_plaintext);
    }

    @Test
    public void roundTripAttached() throws VerificationFailedException {
        final var key = Aegis128L.keygen();
        final var nonce = Aegis128L.noncegen();
        final var plaintext = "0123456789abcdef0123456789ABCDE".getBytes();
        final var ad = "Additional data".getBytes();

        var aegis = new Aegis128L(key, nonce, 16);
        var ciphertext = aegis.encrypt(plaintext, ad);

        aegis = new Aegis128L(key, nonce, 16);
        var recovered_plaintext = aegis.decrypt(ciphertext, ad);
        assertArrayEquals(plaintext, recovered_plaintext);
    }

    @Test
    public void testVector1_128bit() throws VerificationFailedException {
        final var key = hexToBytes("10010000000000000000000000000000");
        final var nonce = hexToBytes("10000200000000000000000000000000");
        final var plaintext = hexToBytes("00000000000000000000000000000000");
        final var ad = new byte[0];
        final var expectedCiphertext = hexToBytes("c1c0e58bd913006feba00f4b3cc3594e");
        final var expectedTag = hexToBytes("abe0ece80c24868a226a35d16bdae37a");

        var aegis = new Aegis128L(key, nonce, 16);
        final var ac = aegis.encryptDetached(plaintext, ad);

        assertArrayEquals(expectedCiphertext, ac.ct);
        assertArrayEquals(expectedTag, ac.tag);
    }

    @Test
    public void testVector1_256bit() throws VerificationFailedException {
        final var key = hexToBytes("10010000000000000000000000000000");
        final var nonce = hexToBytes("10000200000000000000000000000000");
        final var plaintext = hexToBytes("00000000000000000000000000000000");
        final var ad = new byte[0];
        final var expectedCiphertext = hexToBytes("c1c0e58bd913006feba00f4b3cc3594e");
        final var expectedTag = hexToBytes("25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4");

        var aegis = new Aegis128L(key, nonce, 32);
        final var ac = aegis.encryptDetached(plaintext, ad);

        assertArrayEquals(expectedCiphertext, ac.ct);
        assertArrayEquals(expectedTag, ac.tag);
    }

    @Test
    public void testVector2_128bit() throws VerificationFailedException {
        final var key = hexToBytes("10010000000000000000000000000000");
        final var nonce = hexToBytes("10000200000000000000000000000000");
        final var plaintext = new byte[0];
        final var ad = new byte[0];
        final var expectedCiphertext = new byte[0];
        final var expectedTag = hexToBytes("c2b879a67def9d74e6c14f708bbcc9b4");

        var aegis = new Aegis128L(key, nonce, 16);
        final var ac = aegis.encryptDetached(plaintext, ad);

        assertArrayEquals(expectedCiphertext, ac.ct);
        assertArrayEquals(expectedTag, ac.tag);
    }

    @Test
    public void testVector2_256bit() throws VerificationFailedException {
        final var key = hexToBytes("10010000000000000000000000000000");
        final var nonce = hexToBytes("10000200000000000000000000000000");
        final var plaintext = new byte[0];
        final var ad = new byte[0];
        final var expectedCiphertext = new byte[0];
        final var expectedTag = hexToBytes("1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d");

        var aegis = new Aegis128L(key, nonce, 32);
        final var ac = aegis.encryptDetached(plaintext, ad);

        assertArrayEquals(expectedCiphertext, ac.ct);
        assertArrayEquals(expectedTag, ac.tag);
    }

    @Test
    public void testVector3_128bit() throws VerificationFailedException {
        final var key = hexToBytes("10010000000000000000000000000000");
        final var nonce = hexToBytes("10000200000000000000000000000000");
        final var plaintext = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        final var ad = hexToBytes("0001020304050607");
        final var expectedCiphertext = hexToBytes("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84");
        final var expectedTag = hexToBytes("cc6f3372f6aa1bb82388d695c3962d9a");

        var aegis = new Aegis128L(key, nonce, 16);
        final var ac = aegis.encryptDetached(plaintext, ad);

        assertArrayEquals(expectedCiphertext, ac.ct);
        assertArrayEquals(expectedTag, ac.tag);
    }

}
