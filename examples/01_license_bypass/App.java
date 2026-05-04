// "Premium" feature gated by licenseValid() check.
// Without a real license file the program prints "trial mode" forever.
public class App {
    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1_000_000; i++) {
            if (licenseValid()) {
                System.out.println("[" + i + "] PREMIUM FEATURE UNLOCKED");
            } else {
                System.out.println("[" + i + "] trial mode");
            }
            Thread.sleep(500);
        }
    }
    static boolean licenseValid() {
        // Imagine: read /etc/license, validate signature, etc.
        return false;
    }
}
