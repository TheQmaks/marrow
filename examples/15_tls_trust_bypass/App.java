// TLS pinning bypass demo. App holds a pinned TrustManager that
// rejects every server certificate by throwing SecurityException.
// Real TLS validation would normally fail closed. Marrow scripts
// hook the pinned validator's checkServerTrusted to a no-op,
// turning the pinned client into a permissive one without
// rebuilding or re-signing.
import java.lang.management.ManagementFactory;
import java.security.cert.X509Certificate;

public class App {
    // Static check method — easier to demonstrate cleanly than an
    // instance method on an inner class implementing X509TrustManager.
    // (Marrow can hook either; static is one fewer lookup hop and the
    // demo focuses on the trampoline mechanic, not vtable plumbing.)
    public static void checkServerTrusted(X509Certificate[] chain, String authType) {
        throw new SecurityException("CERT_PINNED");
    }

    public static void main(String[] args) throws Exception {
        String n = ManagementFactory.getRuntimeMXBean().getName();
        String pid = n.contains("@") ? n.substring(0, n.indexOf("@")) : n;
        System.out.println("App PID: " + pid);
        System.out.println("App ready - inject marrow now.");
        Thread.sleep(3000);

        try {
            // Simulate the same call the SSL handshake would make.
            // Without marrow this throws SecurityException.
            // With marrow's hook it returns void cleanly.
            checkServerTrusted(new X509Certificate[0], "RSA");
            System.out.println("BYPASSED");
        } catch (SecurityException e) {
            System.out.println("PINNED: " + e.getMessage());
        }
        Thread.sleep(1500);
    }
}
