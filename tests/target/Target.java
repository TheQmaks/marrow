import java.lang.management.ManagementFactory;

public class Target {
    static int counter = 0;
    static volatile String lastMessage = "init";
    static String displayName = "initial";
    static volatile String probeResult = "none";

    // Force Callable to load (we never CALL its methods, so they stay interpreted).
    static {
        try { Class.forName("Callable", true, Target.class.getClassLoader()); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private volatile long  ticks     = 0;
    private volatile int   tag       = 0x13370042;
    private volatile String greeting = "hello from Target";

    public static void main(String[] args) throws Exception {
        long pid = Long.parseLong(
            ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);
        System.out.println("Target PID: " + pid);
        System.out.println("Target thread: " + Thread.currentThread().getName());
        System.out.flush();

        Target t = new Target();
        long started = System.currentTimeMillis();
        while (true) {
            counter++;
            t.tick(counter);
            if (counter % 20 == 0) {
                System.out.println("tick=" + counter
                    + " uptime=" + (System.currentTimeMillis() - started) + "ms"
                    + " greeting=" + t.greeting
                    + " displayName=" + displayName
                    + " probe=" + probeResult);
            }
            Thread.sleep(500);
        }
    }
    void tick(int n) {
        this.ticks = n;
        this.tag ^= 0x9E3779B1;
        lastMessage = "tick #" + n;
    }
}
