// Login app that compares password via String.equals().
// We don't see plaintext attempts — they're entered by user.
import java.util.Scanner;

public class App {
    static String correctPassword = "hunter2";

    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        for (int i = 0; i < 100; i++) {
            System.out.print("password: ");
            String p = s.nextLine();
            if (checkPassword(p)) {
                System.out.println("authenticated");
            } else {
                System.out.println("denied");
            }
        }
    }

    static boolean checkPassword(String input) {
        return correctPassword.equals(input);
    }
}
