import com.github.cfrg.aegis.Aegis128L;
import java.util.Random;

public class BenchmarkAegis128L {
  private static final int WARMUP_ITERATIONS = 1000;
  private static final int BENCHMARK_ITERATIONS = 10000;
  private static final int[] MESSAGE_SIZES = {16, 64, 256, 1024, 4096, 16384, 65536};
  private static final int[] AD_SIZES = {0, 16, 64, 256};
  private static final int[] TAG_LENGTHS = {16, 32};

  public static void main(String[] args) {
    System.out.println("AEGIS-128L Benchmark Results");
    System.out.println("============================");
    System.out.println();

    for (int tagLength : TAG_LENGTHS) {
      System.out.println("Tag Length: " + tagLength + " bytes");
      System.out.println("---------------------------");

      for (int adSize : AD_SIZES) {
        System.out.println("Associated Data Size: " + adSize + " bytes");
        System.out.println(
            String.format(
                "%-10s %-15s %-15s %-15s %-15s",
                "Msg Size",
                "Encrypt (ops/s)",
                "Decrypt (ops/s)",
                "Encrypt (MB/s)",
                "Decrypt (MB/s)"));

        for (int msgSize : MESSAGE_SIZES) {
          BenchmarkResult result = benchmarkOperations(msgSize, adSize, tagLength);
          System.out.println(
              String.format(
                  "%-10d %-15.0f %-15.0f %-15.2f %-15.2f",
                  msgSize,
                  result.encryptOpsPerSec,
                  result.decryptOpsPerSec,
                  result.encryptMBPerSec,
                  result.decryptMBPerSec));
        }
        System.out.println();
      }
    }
  }

  private static BenchmarkResult benchmarkOperations(int msgSize, int adSize, int tagLength) {
    byte[] key = Aegis128L.keygen();
    byte[] nonce = Aegis128L.noncegen();
    byte[] message = new byte[msgSize];
    byte[] ad = new byte[adSize];
    new Random(42).nextBytes(message);
    new Random(43).nextBytes(ad);

    warmup(key, nonce, message, ad, tagLength);

    double encryptOpsPerSec = benchmarkEncrypt(key, nonce, message, ad, tagLength);
    double decryptOpsPerSec = benchmarkDecrypt(key, nonce, message, ad, tagLength);

    double encryptMBPerSec = (encryptOpsPerSec * msgSize) / (1024.0 * 1024.0);
    double decryptMBPerSec = (decryptOpsPerSec * msgSize) / (1024.0 * 1024.0);

    return new BenchmarkResult(
        encryptOpsPerSec, decryptOpsPerSec, encryptMBPerSec, decryptMBPerSec);
  }

  private static void warmup(byte[] key, byte[] nonce, byte[] message, byte[] ad, int tagLength) {
    try {
      for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        Aegis128L cipher = new Aegis128L(key, nonce, tagLength);
        byte[] ciphertext = cipher.encrypt(message, ad);
        Aegis128L decipher = new Aegis128L(key, nonce, tagLength);
        decipher.decrypt(ciphertext, ad);
      }
    } catch (Exception e) {
      throw new RuntimeException("Warmup failed", e);
    }
  }

  private static double benchmarkEncrypt(
      byte[] key, byte[] nonce, byte[] message, byte[] ad, int tagLength) {
    try {
      long startTime = System.nanoTime();
      for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        Aegis128L cipher = new Aegis128L(key, nonce, tagLength);
        cipher.encrypt(message, ad);
      }
      long endTime = System.nanoTime();
      double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
      return BENCHMARK_ITERATIONS / elapsedSeconds;
    } catch (Exception e) {
      throw new RuntimeException("Encrypt benchmark failed", e);
    }
  }

  private static double benchmarkDecrypt(
      byte[] key, byte[] nonce, byte[] message, byte[] ad, int tagLength) {
    try {
      Aegis128L cipher = new Aegis128L(key, nonce, tagLength);
      byte[] ciphertext = cipher.encrypt(message, ad);

      long startTime = System.nanoTime();
      for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        Aegis128L decipher = new Aegis128L(key, nonce, tagLength);
        decipher.decrypt(ciphertext, ad);
      }
      long endTime = System.nanoTime();
      double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
      return BENCHMARK_ITERATIONS / elapsedSeconds;
    } catch (Exception e) {
      throw new RuntimeException("Decrypt benchmark failed", e);
    }
  }

  private static class BenchmarkResult {
    final double encryptOpsPerSec;
    final double decryptOpsPerSec;
    final double encryptMBPerSec;
    final double decryptMBPerSec;

    BenchmarkResult(
        double encryptOpsPerSec,
        double decryptOpsPerSec,
        double encryptMBPerSec,
        double decryptMBPerSec) {
      this.encryptOpsPerSec = encryptOpsPerSec;
      this.decryptOpsPerSec = decryptOpsPerSec;
      this.encryptMBPerSec = encryptMBPerSec;
      this.decryptMBPerSec = decryptMBPerSec;
    }
  }
}
