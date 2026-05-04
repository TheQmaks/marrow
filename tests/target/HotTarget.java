// Moderate-frequency hot-tick target (~1000 Hz). Safer for hooking
// without a safepoint coordinator while still showing measurable
// per-call overhead.
import java.lang.management.ManagementFactory;
public class HotTarget {
    public static volatile long counter = 0;
    public static volatile long startNs   = 0;

    static { try { Class.forName("HotTarget", true, HotTarget.class.getClassLoader()); }
             catch (Exception e) { throw new RuntimeException(e); } }

    public static void main(String[] args) throws Exception {
        long pid = Long.parseLong(
            ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);
        System.out.println("HotTarget PID: " + pid);
        System.out.flush();
        startNs = System.nanoTime();
        long lastReport = startNs;
        while (true) {
            tick();
            counter++;
            // No sleep — drives ~20MHz. Tests if hook patch survives
            // truly hot dispatch without safepoint coordination.
            long now = System.nanoTime();
            if (now - lastReport > 1_000_000_000L) {
                System.out.printf("rate=%d ticks/sec  total=%d%n",
                    counter * 1_000_000_000L / (now - startNs), counter);
                System.out.flush();
                lastReport = now;
            }
        }
    }

    public static volatile long tickWork = 0;
    // Volatile field write — observable side effect that prevents the JIT
    // from inlining tick() away into main's loop body. Without this, the
    // entire call disappears and our hook has nothing to attach to.
    public static void tick() { tickWork++; }
}
