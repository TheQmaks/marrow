// App opens a TCP socket, reads bytes from server.
// Java side calls SocketInputStream.read() which calls native ws2_32!recv.
// We want to see the RAW bytes coming in — hook native recv.
import java.net.*;
import java.io.*;

public class App {
    public static void main(String[] args) throws Exception {
        // Listen on localhost so we can self-test.
        new Thread(() -> {
            try {
                ServerSocket srv = new ServerSocket(31337);
                while (true) {
                    Socket cli = srv.accept();
                    cli.getOutputStream().write("HELLO FROM SERVER\n".getBytes());
                    cli.close();
                }
            } catch (Exception e) {}
        }).start();
        Thread.sleep(500);
        for (int i = 0; i < 1_000_000; i++) {
            Socket s = new Socket("localhost", 31337);
            byte[] buf = new byte[64];
            int n = s.getInputStream().read(buf);
            System.out.println("recv " + n + " bytes");
            s.close();
            Thread.sleep(2000);
        }
    }
}
