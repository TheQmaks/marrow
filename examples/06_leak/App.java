// App with subtle memory leak — Strings accumulating in static list.
import java.util.*;

public class App {
    static List<String> cache = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1_000_000; i++) {
            // "Cache" never evicted — pure leak.
            cache.add("entry-" + i + "-" + System.nanoTime());
            Thread.sleep(50);
            if (i % 100 == 0) {
                System.out.println("cache size = " + cache.size());
            }
        }
    }
}
