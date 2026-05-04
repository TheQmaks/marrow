// Closed-source service receives User + Permission objects. Хотим увидеть что
// именно туда летит, не имея сорсов и не запуская debugger.
class User {
    String name;
    int age;
    String email;
    User(String n, int a, String e) { name=n; age=a; email=e; }
}

class Permission {
    String resource;
    boolean canWrite;
    Permission(String r, boolean w) { resource=r; canWrite=w; }
}

public class App {
    public static void main(String[] args) throws Exception {
        User[] users = {
            new User("alice", 30, "alice@corp.com"),
            new User("bob", 25, "bob@corp.com"),
            new User("admin", 99, "root@corp.com")
        };
        Permission[] perms = {
            new Permission("/api/secret", false),
            new Permission("/api/admin", true)
        };
        for (int i = 0; i < 1_000_000; i++) {
            User u = users[i % users.length];
            Permission p = perms[i % perms.length];
            authorize(u, p);
            Thread.sleep(2000);
        }
    }

    // Closed-source authorization function. Takes two objects.
    static boolean authorize(User u, Permission p) {
        if (u.age < 18) return false;
        if (!p.canWrite) return false;
        System.out.println("AUTH OK: " + u.name + " → " + p.resource);
        return true;
    }
}
