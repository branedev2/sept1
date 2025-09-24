public class UserService {
    private static final String DB_PASSWORD = "root123"; // Issue: Hardcoded password
    
    public String getUserData(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId; // Issue: SQL injection
        return Database.execute(query);
    }
}
