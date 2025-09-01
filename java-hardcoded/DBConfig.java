package config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import com.mongodb.MongoClient; 
import com.mongodb.MongoClientURI;  

public class DBConfig {
    

    public static Connection getConnection() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.jdbc.Driver");
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/notas_db", "root", "root");
    }

    public static MongoClient getNoSqlConnection() {
        return new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
    }

    
}