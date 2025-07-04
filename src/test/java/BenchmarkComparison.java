import com.github.cfrg.aegis.Aegis128L;
import com.github.cfrg.aegis.Aegis256;
import java.util.Random;

public class BenchmarkComparison {
  private static final int WARMUP_ITERATIONS = 1000;
  private static final int BENCHMARK_ITERATIONS = 10000;
  private static final int[] MESSAGE_SIZES = {1024, 4096, 16384, 65536};
  private static final int AD_SIZE = 16;
  private static final int TAG_LENGTH = 16;

  public static void main(String[] args) {
    System.out.println("AEGIS-128L vs AEGIS-256 Performance Comparison");
    System.out.println("===============================================");
    System.out.println("(Using 16-byte tags and 16-byte associated data)");
    System.out.println();

    System.out.println(
        String.format(
            "%-10s %-15s %-15s %-15s %-15s %-15s",
            "Msg Size", "128L Enc MB/s", "256 Enc MB/s", "128L Dec MB/s", "256 Dec MB/s", "Ratio"));

    for (int msgSize : MESSAGE_SIZES) {
      ComparisonResult result = benchmarkComparison(msgSize);
      System.out.println(
          String.format(
              "%-10d %-15.2f %-15.2f %-15.2f %-15.2f %-15.2f",
              msgSize,
              result.aegis128L_encMBPerSec,
              result.aegis256_encMBPerSec,
              result.aegis128L_decMBPerSec,
              result.aegis256_decMBPerSec,
              result.aegis128L_encMBPerSec / result.aegis256_encMBPerSec));
    }
    System.out.println();

    System.out.println("Summary:");
    System.out.println("--------");
    System.out.println("Ratio > 1.0 indicates AEGIS-128L is faster");
    System.out.println("Ratio < 1.0 indicates AEGIS-256 is faster");
    System.out.println(
        "AEGIS-128L typically provides higher throughput due to larger state parallelism");
    System.out.println("AEGIS-256 provides stronger security with 256-bit keys");
  }

  private static ComparisonResult benchmarkComparison(int msgSize) {
    byte[] key128L = Aegis128L.keygen();
    byte[] nonce128L = Aegis128L.noncegen();
    byte[] key256 = Aegis256.keygen();
    byte[] nonce256 = Aegis256.noncegen();
    byte[] message = new byte[msgSize];
    byte[] ad = new byte[AD_SIZE];
    new Random(42).nextBytes(message);
    new Random(43).nextBytes(ad);

    warmup128L(key128L, nonce128L, message, ad);
    warmup256(key256, nonce256, message, ad);

    double aegis128L_encOpsPerSec = benchmarkEncrypt128L(key128L, nonce128L, message, ad);
    double aegis128L_decOpsPerSec = benchmarkDecrypt128L(key128L, nonce128L, message, ad);
    double aegis256_encOpsPerSec = benchmarkEncrypt256(key256, nonce256, message, ad);
    double aegis256_decOpsPerSec = benchmarkDecrypt256(key256, nonce256, message, ad);

    double aegis128L_encMBPerSec = (aegis128L_encOpsPerSec * msgSize) / (1024.0 * 1024.0);
    double aegis128L_decMBPerSec = (aegis128L_decOpsPerSec * msgSize) / (1024.0 * 1024.0);
    double aegis256_encMBPerSec = (aegis256_encOpsPerSec * msgSize) / (1024.0 * 1024.0);
    double aegis256_decMBPerSec = (aegis256_decOpsPerSec * msgSize) / (1024.0 * 1024.0);

    return new ComparisonResult(
        aegis128L_encMBPerSec, aegis256_encMBPerSec, aegis128L_decMBPerSec, aegis256_decMBPerSec);
  }

  private static void warmup128L(byte[] key, byte[] nonce, byte[] message, byte[] ad) {
    try {
      for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        Aegis128L cipher = new Aegis128L(key, nonce, TAG_LENGTH);
        byte[] ciphertext = cipher.encrypt(message, ad);
        Aegis128L decipher = new Aegis128L(key, nonce, TAG_LENGTH);
        decipher.decrypt(ciphertext, ad);
      }
    } catch (Exception e) {
      throw new RuntimeException("128L warmup failed", e);
    }
  }

  private static void warmup256(byte[] key, byte[] nonce, byte[] message, byte[] ad) {
    try {
      for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        Aegis256 cipher = new Aegis256(key, nonce, TAG_LENGTH);
        byte[] ciphertext = cipher.encrypt(message, ad);
        Aegis256 decipher = new Aegis256(key, nonce, TAG_LENGTH);
        decipher.decrypt(ciphertext, ad);
      }
    } catch (Exception e) {
      throw new RuntimeException("256 warmup failed", e);
    }
  }

  private static double benchmarkEncrypt128L(byte[] key, byte[] nonce, byte[] message, byte[] ad) {
    try {
      long startTime = System.nanoTime();
      for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        Aegis128L cipher = new Aegis128L(key, nonce, TAG_LENGTH);
        cipher.encrypt(message, ad);
      }
      long endTime = System.nanoTime();
      double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
      return BENCHMARK_ITERATIONS / elapsedSeconds;
    } catch (Exception e) {
      throw new RuntimeException("128L encrypt benchmark failed", e);
    }
  }

  private static double benchmarkDecrypt128L(byte[] key, byte[] nonce, byte[] message, byte[] ad) {
    try {
      Aegis128L cipher = new Aegis128L(key, nonce, TAG_LENGTH);
      byte[] ciphertext = cipher.encrypt(message, ad);

      long startTime = System.nanoTime();
      for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        Aegis128L decipher = new Aegis128L(key, nonce, TAG_LENGTH);
        decipher.decrypt(ciphertext, ad);
      }
      long endTime = System.nanoTime();
      double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
      return BENCHMARK_ITERATIONS / elapsedSeconds;
    } catch (Exception e) {
      throw new RuntimeException("128L decrypt benchmark failed", e);
    }
  }

  private static double benchmarkEncrypt256(byte[] key, byte[] nonce, byte[] message, byte[] ad) {
    try {
      long startTime = System.nanoTime();
      for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        Aegis256 cipher = new Aegis256(key, nonce, TAG_LENGTH);
        cipher.encrypt(message, ad);
      }
      long endTime = System.nanoTime();
      double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
      return BENCHMARK_ITERATIONS / elapsedSeconds;
    } catch (Exception e) {
      throw new RuntimeException("256 encrypt benchmark failed", e);
    }
  }

  private static double benchmarkDecrypt256(byte[] key, byte[] nonce, byte[] message, byte[] ad) {
    try {
      Aegis256 cipher = new Aegis256(key, nonce, TAG_LENGTH);
      byte[] ciphertext = cipher.encrypt(message, ad);

      long startTime = System.nanoTime();
      for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        Aegis256 decipher = new Aegis256(key, nonce, TAG_LENGTH);
        decipher.decrypt(ciphertext, ad);
      }
      long endTime = System.nanoTime();
      double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
      return BENCHMARK_ITERATIONS / elapsedSeconds;
    } catch (Exception e) {
      throw new RuntimeException("256 decrypt benchmark failed", e);
    }
  }

  private static class ComparisonResult {
    final double aegis128L_encMBPerSec;
    final double aegis256_encMBPerSec;
    final double aegis128L_decMBPerSec;
    final double aegis256_decMBPerSec;

    ComparisonResult(
        double aegis128L_encMBPerSec,
        double aegis256_encMBPerSec,
        double aegis128L_decMBPerSec,
        double aegis256_decMBPerSec) {
      this.aegis128L_encMBPerSec = aegis128L_encMBPerSec;
      this.aegis256_encMBPerSec = aegis256_encMBPerSec;
      this.aegis128L_decMBPerSec = aegis128L_decMBPerSec;
      this.aegis256_decMBPerSec = aegis256_decMBPerSec;
    }
  }
}
