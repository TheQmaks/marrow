// Multi-threaded hook stress target. N worker threads each call
// MultiThread.work(int) M times in tight loop. Marrow scripts can
// hook work() and verify they observe N*M total fires across all
// threads — exercising the worker thread's _fie/_fce re-pin races
// against dispatch reads on multiple JVM threads.
//
// The method itself is trivial (a + 1) so loop overhead is dominated
// by hook dispatch. Each worker also keeps a per-thread sum so the
// driver can detect lost increments.
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.lang.management.ManagementFactory;

public class MultiThread {
    // Hookable method. Primitive args + return so we can hit both
    // sync .implementation and async .attach paths cleanly.
    public static int work(int n) {
        return n + 1;
    }

    public static void main(String[] args) throws Exception {
        int nThreads = args.length > 0 ? Integer.parseInt(args[0]) : 8;
        int iterPer  = args.length > 1 ? Integer.parseInt(args[1]) : 5000;

        String pid = ManagementFactory.getRuntimeMXBean().getName();
        if (pid.contains("@")) pid = pid.substring(0, pid.indexOf("@"));
        System.out.println("MultiThread PID: " + pid);
        System.out.println("threads=" + nThreads + " iter=" + iterPer);

        // Wait window for marrow to inject + push the hook script.
        // 4 seconds covers slow CI runners; local runs barely notice.
        Thread.sleep(4000);
        System.out.println("starting workers");

        AtomicLong total = new AtomicLong();
        ExecutorService pool = Executors.newFixedThreadPool(nThreads);
        CountDownLatch ready = new CountDownLatch(nThreads);
        CountDownLatch done  = new CountDownLatch(nThreads);

        for (int t = 0; t < nThreads; ++t) {
            final int tid = t;
            pool.submit(() -> {
                ready.countDown();
                try { ready.await(); } catch (InterruptedException ie) {}
                long sum = 0;
                for (int i = 0; i < iterPer; ++i) {
                    sum += work(tid * 1_000_000 + i);
                }
                total.addAndGet(sum);
                done.countDown();
            });
        }
        done.await();
        pool.shutdown();

        System.out.println("workers done total_sum=" + total.get());
        // Park briefly so marrow can drain stats before exit.
        Thread.sleep(2000);
        System.out.println("MultiThread exit");
    }
}
