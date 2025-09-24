// Sample Java file with vulnerabilities

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;
import java.io.File;
import java.io.FileInputStream;
import java.util.Random;

public class VulnerableJava {
    
    // Hardcoded credentials vulnerability
    private static final String DB_PASSWORD = "hardcoded_password";
    
    public static void main(String[] args) {
        try {
            // Insecure random number generator
            Random random = new Random();  // Insecure random
            int randomValue = random.nextInt();
            
            // Connect to database
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "root", DB_PASSWORD);
            
            // SQL Injection vulnerability
            String userId = args[0];
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);  // SQL Injection
            
            // Path traversal vulnerability
            String fileName = args[1];
            File file = new File("data/" + fileName);  // Path traversal
            FileInputStream fis = new FileInputStream(file);
            
            // Command injection vulnerability
            String command = args[2];
            Runtime.getRuntime().exec("cmd.exe /c " + command);  // Command injection
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Another SQL Injection vulnerability
    public void searchUsers(String searchTerm) throws Exception {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/mydb", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'");  // SQL Injection
    }
}
