// App makes various HTTP requests; we want to log all URLs without source.
import java.net.*;
import java.io.*;

public class App {
    public static void main(String[] args) throws Exception {
        String[] urls = {
            "http://example.com/api/login",
            "https://api.example.com/v2/users?token=secret123",
            "http://internal/health",
            "https://telemetry.tracker.com/beacon"
        };
        for (int i = 0; i < 1_000_000; i++) {
            String u = urls[i % urls.length];
            try {
                URL url = new URL(u);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod("GET");
                con.setRequestProperty("X-Auth", "bearer xyz");
                con.getResponseCode();
            } catch (Exception e) {
                System.out.println("err: " + e.getMessage());
            }
            Thread.sleep(2000);
        }
    }
}
