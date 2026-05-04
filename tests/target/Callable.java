public class Callable {
    static int counter = 0;

    public static int neverCalled() { return 0xCAFEBABE; }
    public static long alsoNever() { return 0xDEADBEEFCAFEBABEL; }
    public static void voidNever() {}
    public static void voidWork() { counter++; }
    public static int sumThings() { return counter + 7; }

    // Multi-arg primitive tests.
    public static int addInts(int a, int b) { return a + b; }
    public static int sumFour(int a, int b, int c, int d) { return a + b + c + d; }
    public static long mulLong(long a, long b) { return a * b; }
    public static long mixed(int i, long j) { return j + i; }
    public static double addDoubles(double a, double b) { return a + b; }
    public static int boolToInt(boolean b) { return b ? 1 : 0; }

    // Object-arg tests. Return the arg's hashCode so we can verify identity.
    public static int strHash(String s) { return s == null ? -1 : s.hashCode(); }
    public static int strLen(String s)  { return s == null ? -1 : s.length(); }
}
