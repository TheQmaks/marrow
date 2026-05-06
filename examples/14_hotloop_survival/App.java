// Sustained-hot-loop call site that v0.3-era instrumentation tools
// silently lose mid-loop because HotSpot tier-up's the method and
// publishes a fresh nmethod whose verified entry point bypasses the
// original hook trampoline. v0.5 disables JIT for hooked methods at
// install time, so the trampoline survives indefinitely.
//
// Run after the marrow agent is injected; watch the hooked counter
// stay in lockstep with the loop iteration count.
public class App {
    public static int score(int a, int b) {
        return a * 31 + b;
    }

    public static void main(String[] args) throws Exception {
        // JDK 8 compatible PID extraction. ProcessHandle.current() is
        // JDK 9+; fall back to ManagementFactory's "pid@host" format.
        String name = java.lang.management.ManagementFactory
                          .getRuntimeMXBean().getName();
        String pid = name.contains("@") ? name.substring(0, name.indexOf("@"))
                                        : name;
        System.out.println("App PID: " + pid);
        System.out.println("App ready — inject marrow now.");
        Thread.sleep(3000);

        long sum = 0;
        // 50,000 invocations: HotSpot's default Tier3InvocationThreshold
        // (200) trips around iter 200, Tier4 around 10,000. v0.3 lost
        // 93% of fires past tier-up; v0.5 keeps every one.
        for (int i = 0; i < 50_000; ++i) {
            sum += score(i, i * 2);
        }
        System.out.println("loop done, sum=" + sum);
        Thread.sleep(2000);   // give marrow time to drain final stats
    }
}
