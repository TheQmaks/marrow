// Tiny "game" — score increments by 1 every tick. Player struggles.
public class Game {
    int score = 0;
    int health = 100;
    String playerName = "noob";

    public static void main(String[] args) throws Exception {
        Game g = new Game();
        for (int i = 0; i < 1_000_000; i++) {
            g.score += 1;
            if (i % 5 == 0) {
                g.health -= 1;
            }
            System.out.println("score=" + g.score +
                " health=" + g.health +
                " player=" + g.playerName);
            Thread.sleep(500);
            if (g.health <= 0) {
                System.out.println("GAME OVER");
                return;
            }
        }
    }
}
