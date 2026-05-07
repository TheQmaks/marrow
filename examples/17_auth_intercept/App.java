// Auth bypass demo. App calls login(user, pass) with wrong
// credentials — the real method would return false. Marrow's
// .implementation = fn replaces the return value with true,
// optionally logging the attempted credentials in the process.
//
// Vanilla-JVM equivalent of Frida's "force login success" recipe.
import java.lang.management.ManagementFactory;

public class App {
    public static boolean login(String user, String pass) {
        // Real check: only the canonical admin gets in.
        return "admin".equals(user) && "s3cret".equals(pass);
    }

    public static void main(String[] args) throws Exception {
        String n = ManagementFactory.getRuntimeMXBean().getName();
        String pid = n.contains("@") ? n.substring(0, n.indexOf("@")) : n;
        System.out.println("App PID: " + pid);
        System.out.println("App ready - inject marrow now.");
        Thread.sleep(3000);

        // These credentials are wrong on purpose. Without marrow,
        // login() returns false. With marrow's hook, it returns
        // true AND the attempted creds get logged.
        boolean ok = login("guest", "wrong-pwd");
        System.out.println("login result: " + ok);
        Thread.sleep(1500);
    }
}
