// App: validates Order, then charges credit card.
// validateOrder THROWS if price > $100. Хотим обмануть: проходим validation
// + сбиваем цену так чтобы chargeCard списал $0.
class Order {
    String product;
    int quantity;
    double totalPrice;
    Order(String p, int q, double price) {
        this.product = p; this.quantity = q; this.totalPrice = price;
    }
}

public class App {
    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1_000_000; i++) {
            Order o = new Order("Premium-Widget-" + i, 5, 9999.99);
            try {
                validateOrder(o);
                chargeCard(o);
            } catch (Exception e) {
                System.out.println("REJECTED: " + e.getMessage());
            }
            Thread.sleep(2000);
        }
    }
    static void validateOrder(Order o) {
        if (o.totalPrice > 100.0)
            throw new IllegalArgumentException("price too high: $" + o.totalPrice);
    }
    static void chargeCard(Order o) {
        System.out.println("CHARGED $" + o.totalPrice + " for " + o.product +
                           " x" + o.quantity);
    }
}
