import java.io.*;
import java.sql.*;
import java.util.*;
import java.net.*;
import javax.sql.DataSource;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.util.zip.ZipFile;
import java.util.Scanner;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

public class ResourceLeakExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=missing-release-of-resources@v1.0 defects=1}
    public static void bad_case_1() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("config.properties");
            Properties props = new Properties();
            props.load(fis);
            System.out.println("Loaded properties: " + props.size());
            // ruleid: java-missing-release-of-resources
            // Resource is not closed in normal execution path
        } catch (IOException e) {
            e.printStackTrace();
        }
        // fis is never closed
    }

    public static void bad_case_2() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            // ruleid: java-missing-release-of-resources
            ResultSet rs = stmt.executeQuery("SELECT * FROM users");
            
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
            // rs and stmt are not closed
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    public static void bad_case_3() {
        BufferedReader reader = null;
        try {
            // ruleid: java-missing-release-of-resources
            reader = new BufferedReader(new FileReader("data.txt"));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            // No explicit close in normal path
        } catch (IOException e) {
            e.printStackTrace();
            try {
                if (reader != null) reader.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        // reader is only closed in exception path
    }

    public static void bad_case_4() {
        Socket socket = null;
        try {
            // ruleid: java-missing-release-of-resources
            socket = new Socket("localhost", 8080);
            OutputStream out = socket.getOutputStream();
            out.write("Hello Server".getBytes());
            // Neither socket nor output stream is closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_5() {
        ZipFile zipFile = null;
        try {
            // ruleid: java-missing-release-of-resources
            zipFile = new ZipFile("archive.zip");
            Enumeration<? extends java.util.zip.ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                System.out.println(entries.nextElement().getName());
            }
            // zipFile is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_6() {
        InputStream inputStream = null;
        try {
            URL url = new URL("https://example.com");
            // ruleid: java-missing-release-of-resources
            inputStream = url.openStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                System.out.write(buffer, 0, bytesRead);
            }
            // inputStream is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_7() {
        Scanner scanner = null;
        try {
            // ruleid: java-missing-release-of-resources
            scanner = new Scanner(new File("input.txt"));
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            // scanner is not closed
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_8() {
        FileChannel sourceChannel = null;
        FileChannel destChannel = null;
        try {
            // ruleid: java-missing-release-of-resources
            sourceChannel = new FileInputStream("source.txt").getChannel();
            destChannel = new FileOutputStream("destination.txt").getChannel();
            destChannel.transferFrom(sourceChannel, 0, sourceChannel.size());
            // Neither channel is closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_9() {
        RandomAccessFile file = null;
        try {
            // ruleid: java-missing-release-of-resources
            file = new RandomAccessFile("data.bin", "rw");
            file.writeInt(42);
            file.seek(0);
            int value = file.readInt();
            System.out.println("Value: " + value);
            // file is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ruleid: java-missing-release-of-resources
            pstmt = conn.prepareStatement("INSERT INTO logs VALUES (?, ?)");
            pstmt.setString(1, "info");
            pstmt.setString(2, "Application started");
            pstmt.executeUpdate();
            // pstmt is not closed
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    public static void bad_case_11() {
        try {
            // ruleid: java-missing-release-of-resources
            BufferedImage image = ImageIO.read(new File("input.jpg"));
            Graphics2D g2d = image.createGraphics();
            g2d.drawString("Watermark", 50, 50);
            ImageIO.write(image, "jpg", new File("output.jpg"));
            // g2d is not disposed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_12() {
        PrintWriter writer = null;
        try {
            // ruleid: java-missing-release-of-resources
            writer = new PrintWriter(new FileWriter("output.log"));
            writer.println("Log entry at " + new Date());
            // writer is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_13() {
        DataSource dataSource = getDataSource(); // Assume this method exists
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = dataSource.getConnection();
            // ruleid: java-missing-release-of-resources
            stmt = conn.createStatement();
            stmt.executeUpdate("UPDATE users SET active = true");
            // stmt is not closed
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    public static void bad_case_14() {
        try {
            // ruleid: java-missing-release-of-resources
            DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get("."));
            for (Path file: stream) {
                System.out.println(file.getFileName());
            }
            // stream is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_15() {
        ObjectOutputStream out = null;
        try {
            // ruleid: java-missing-release-of-resources
            out = new ObjectOutputStream(new FileOutputStream("object.ser"));
            out.writeObject(new Date());
            // out is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe Code)

    public static void good_case_1() {
        // ok: java-missing-release-of-resources
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            Properties props = new Properties();
            props.load(fis);
            System.out.println("Loaded properties: " + props.size());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_2() {
        // ok: java-missing-release-of-resources
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM users")) {
            
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_3() {
        // ok: java-missing-release-of-resources
        try (BufferedReader reader = new BufferedReader(new FileReader("data.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_4() {
        // ok: java-missing-release-of-resources
        try (Socket socket = new Socket("localhost", 8080);
             OutputStream out = socket.getOutputStream()) {
            out.write("Hello Server".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_5() {
        // ok: java-missing-release-of-resources
        try (ZipFile zipFile = new ZipFile("archive.zip")) {
            Enumeration<? extends java.util.zip.ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                System.out.println(entries.nextElement().getName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_6() {
        // ok: java-missing-release-of-resources
        try (InputStream inputStream = new URL("https://example.com").openStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                System.out.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_7() {
        // ok: java-missing-release-of-resources
        try (Scanner scanner = new Scanner(new File("input.txt"))) {
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_8() {
        // ok: java-missing-release-of-resources
        try (FileChannel sourceChannel = new FileInputStream("source.txt").getChannel();
             FileChannel destChannel = new FileOutputStream("destination.txt").getChannel()) {
            destChannel.transferFrom(sourceChannel, 0, sourceChannel.size());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_9() {
        // ok: java-missing-release-of-resources
        try (RandomAccessFile file = new RandomAccessFile("data.bin", "rw")) {
            file.writeInt(42);
            file.seek(0);
            int value = file.readInt();
            System.out.println("Value: " + value);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_10() {
        // ok: java-missing-release-of-resources
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             PreparedStatement pstmt = conn.prepareStatement("INSERT INTO logs VALUES (?, ?)")) {
            pstmt.setString(1, "info");
            pstmt.setString(2, "Application started");
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_11() {
        try {
            BufferedImage image = ImageIO.read(new File("input.jpg"));
            // ok: java-missing-release-of-resources
            Graphics2D g2d = image.createGraphics();
            try {
                g2d.drawString("Watermark", 50, 50);
                ImageIO.write(image, "jpg", new File("output.jpg"));
            } finally {
                g2d.dispose(); // Properly disposing the graphics context
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_12() {
        // ok: java-missing-release-of-resources
        try (PrintWriter writer = new PrintWriter(new FileWriter("output.log"))) {
            writer.println("Log entry at " + new Date());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_13() {
        DataSource dataSource = getDataSource(); // Assume this method exists
        // ok: java-missing-release-of-resources
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("UPDATE users SET active = true");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_14() {
        // ok: java-missing-release-of-resources
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get("."))) {
            for (Path file: stream) {
                System.out.println(file.getFileName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_15() {
        // ok: java-missing-release-of-resources
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("object.ser"))) {
            out.writeObject(new Date());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Helper method for examples
    private static DataSource getDataSource() {
        // This would be implemented in a real application
        return null;
    }
}
// {/fact}