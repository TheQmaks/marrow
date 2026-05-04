// App with "godmode" flag controlled internally.
// We want to toggle it via hotkey from outside the app — no UI.
public class App {
    static volatile boolean godmode = false;
    static volatile int health = 100;

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1_000_000; i++) {
            if (!godmode) {
                health -= 1;   // bleeding to death
            }
            System.out.println("health=" + health + " godmode=" + godmode);
            Thread.sleep(500);
            if (health <= 0) { System.out.println("DEAD"); return; }
        }
    }
}
