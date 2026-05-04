// App mutates a static counter from many code paths.
// "Who's writing to it?" — classic concurrency mystery.
public class App {
    static volatile int counter = 0;

    public static void main(String[] args) throws Exception {
        new Thread(() -> { while (true) { incA(); sleep(500); } }).start();
        new Thread(() -> { while (true) { incB(); sleep(750); } }).start();
        for (int i = 0; i < 1_000_000; i++) {
            mainThreadInc();
            System.out.println("counter=" + counter);
            Thread.sleep(1000);
        }
    }
    static void incA() { counter++; }
    static void incB() { counter += 10; }
    static void mainThreadInc() { counter += 100; }
    static void sleep(long ms) { try { Thread.sleep(ms); } catch (Exception e){} }
}
