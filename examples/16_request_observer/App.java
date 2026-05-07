// HTTP-style request handler logger demo. App processes a fixed
// list of requests through a static handle(String) method. Marrow
// scripts attach a passive observer that logs every call without
// changing behavior. The vanilla-JVM equivalent of Frida's Activity-
// logging recipe used on Android.
import java.lang.management.ManagementFactory;

public class App {
    public static String handle(String request) {
        // Trivial "service" — pretend to process the request.
        return "OK: " + request.length() + " bytes";
    }

    public static void main(String[] args) throws Exception {
        String n = ManagementFactory.getRuntimeMXBean().getName();
        String pid = n.contains("@") ? n.substring(0, n.indexOf("@")) : n;
        System.out.println("App PID: " + pid);
        System.out.println("App ready - inject marrow now.");
        Thread.sleep(3000);

        String[] reqs = {
            "GET /",
            "POST /api/login",
            "DELETE /user/42",
            "PUT /config",
            "GET /health"
        };
        for (String r : reqs) {
            System.out.println("[handler] " + handle(r));
        }
        // Stay alive long enough for the marrow script's drain to run.
        // Real services keep running anyway; demo just parks here.
        Thread.sleep(8000);
    }
}
