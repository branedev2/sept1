import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");  // User input from the URL

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "user", "password");
            Statement stmt = conn.createStatement();

            // Vulnerability: Concatenation of user input in SQL query
            String query = "SELECT * FROM users WHERE id = " + userId;
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                out.println("User ID: " + rs.getInt("id"));
                out.println("User Name: " + rs.getString("name"));
            }

            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
            out.println("Error: " + e.getMessage());
        } finally {
            out.close();
        }
    }
}

