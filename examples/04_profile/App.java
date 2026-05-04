// App with several methods; figure out which is HOT without source access.
public class App {
    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1_000_000; i++) {
            cold();
            for (int k = 0; k < 50; k++) hot();
            warm();
            Thread.sleep(10);
        }
    }
    static void cold()   { /* slow but rare */ }
    static void warm()   { /* moderate */ }
    static void hot()    { /* called 50× more */ }
    static void unused() { /* never called */ }
}
