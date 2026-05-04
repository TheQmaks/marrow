// App encrypts secret data with AES; only ciphertext goes over the network.
// We want to capture the PLAINTEXT before encryption.
import javax.crypto.*;
import javax.crypto.spec.*;

public class App {
    public static void main(String[] args) throws Exception {
        SecretKey key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        for (int i = 0; i < 1_000_000; i++) {
            String secret = "the password is hunter2 (msg #" + i + ")";
            byte[] ct = c.doFinal(secret.getBytes());
            System.out.println("encrypted: " + ct.length + " bytes");
            Thread.sleep(2000);
        }
    }
}
