import java.io.*;
import java.sql.*;
import java.util.zip.*;
import java.net.*;
import javax.servlet.http.*;
import java.nio.channels.*;
import java.nio.file.*;
import javax.imageio.*;
import java.awt.image.BufferedImage;
import java.util.Scanner;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;

public class ResourceLeakExamples {

    // True Positive Examples (bad cases)

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        FileInputStream fis = null;
        try {
            String fileName = request.getParameter("file");
            fis = new FileInputStream(fileName);
            byte[] data = new byte[1024];
            fis.read(data);
            // ruleid: java-resource-leak-detector
            // Resource leak: FileInputStream is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users");
            
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
            // ruleid: java-resource-leak-detector
            // Resource leak: ResultSet, Statement, and Connection are not closed
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        BufferedReader reader = null;
        try {
            reader = request.getReader();
            String line;
            StringBuilder builder = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }
            response.getWriter().write("Received: " + builder.toString());
            // ruleid: java-resource-leak-detector
            // Resource leak: BufferedReader is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile("archive.zip");
            java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                System.out.println(entry.getName());
            }
            // ruleid: java-resource-leak-detector
            // Resource leak: ZipFile is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        Socket socket = null;
        try {
            socket = new Socket("example.com", 80);
            OutputStream out = socket.getOutputStream();
            out.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes());
            // ruleid: java-resource-leak-detector
            // Resource leak: Socket and OutputStream are not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        FileChannel channel = null;
        try {
            String filePath = request.getParameter("path");
            channel = FileChannel.open(Paths.get(filePath), StandardOpenOption.READ);
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            channel.read(buffer);
            buffer.flip();
            // ruleid: java-resource-leak-detector
            // Resource leak: FileChannel is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        RandomAccessFile file = null;
        try {
            file = new RandomAccessFile("data.bin", "rw");
            file.writeInt(42);
            file.seek(0);
            int value = file.readInt();
            System.out.println("Value: " + value);
            // ruleid: java-resource-leak-detector
            // Resource leak: RandomAccessFile is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        BufferedImage image = null;
        try {
            image = ImageIO.read(new File("image.jpg"));
            int width = image.getWidth();
            int height = image.getHeight();
            System.out.println("Image dimensions: " + width + "x" + height);
            // ruleid: java-resource-leak-detector
            // Resource leak: File input stream created by ImageIO.read is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        Scanner scanner = null;
        try {
            String input = request.getParameter("input");
            scanner = new Scanner(new File(input));
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            // ruleid: java-resource-leak-detector
            // Resource leak: Scanner is not closed
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        InputStream is = null;
        try {
            URL url = new URL("https://example.com");
            is = url.openStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                System.out.write(buffer, 0, bytesRead);
            }
            // ruleid: java-resource-leak-detector
            // Resource leak: InputStream is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(new FileWriter("output.txt"));
            writer.println("Hello, world!");
            writer.flush();
            // ruleid: java-resource-leak-detector
            // Resource leak: PrintWriter and FileWriter are not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(8080);
            Socket clientSocket = serverSocket.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String inputLine = in.readLine();
            System.out.println("Received: " + inputLine);
            // ruleid: java-resource-leak-detector
            // Resource leak: ServerSocket, Socket, BufferedReader, and InputStreamReader are not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        CipherInputStream cis = null;
        try {
            byte[] key = "0123456789abcdef".getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            FileInputStream fis = new FileInputStream("encrypted.data");
            cis = new CipherInputStream(fis, cipher);
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                System.out.write(buffer, 0, bytesRead);
            }
            // ruleid: java-resource-leak-detector
            // Resource leak: CipherInputStream and FileInputStream are not closed
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        Properties props = new Properties();
        FileInputStream configStream = null;
        try {
            configStream = new FileInputStream("config.properties");
            props.load(configStream);
            String value = props.getProperty("key");
            System.out.println("Value: " + value);
            // ruleid: java-resource-leak-detector
            // Resource leak: FileInputStream is not closed
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        PreparedStatement pstmt = null;
        Connection conn = null;
        try {
            String id = request.getParameter("id");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            pstmt.setString(1, id);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                System.out.println(rs.getString("name"));
            }
            // ruleid: java-resource-leak-detector
            // Resource leak: ResultSet, PreparedStatement, and Connection are not closed
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (good cases)

    public void good_case_1(HttpServletRequest request) {
        FileInputStream fis = null;
        try {
            String fileName = request.getParameter("file");
            fis = new FileInputStream(fileName);
            byte[] data = new byte[1024];
            fis.read(data);
            // ok: java-resource-leak-detector
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void good_case_2() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT * FROM users");
            
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            // ok: java-resource-leak-detector
            try {
                if (rs != null) rs.close();
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        BufferedReader reader = null;
        try {
            reader = request.getReader();
            String line;
            StringBuilder builder = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }
            response.getWriter().write("Received: " + builder.toString());
            // ok: java-resource-leak-detector
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void good_case_4() {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile("archive.zip");
            java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                System.out.println(entry.getName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // ok: java-resource-leak-detector
            if (zipFile != null) {
                try {
                    zipFile.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void good_case_5() {
        try (Socket socket = new Socket("example.com", 80);
             OutputStream out = socket.getOutputStream()) {
            // ok: java-resource-leak-detector
            out.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        String filePath = request.getParameter("path");
        try (FileChannel channel = FileChannel.open(Paths.get(filePath), StandardOpenOption.READ)) {
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            // ok: java-resource-leak-detector
            channel.read(buffer);
            buffer.flip();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try (RandomAccessFile file = new RandomAccessFile("data.bin", "rw")) {
            // ok: java-resource-leak-detector
            file.writeInt(42);
            file.seek(0);
            int value = file.readInt();
            System.out.println("Value: " + value);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try (InputStream is = new FileInputStream("image.jpg")) {
            // ok: java-resource-leak-detector
            BufferedImage image = ImageIO.read(is);
            int width = image.getWidth();
            int height = image.getHeight();
            System.out.println("Image dimensions: " + width + "x" + height);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(HttpServletRequest request) {
        String input = request.getParameter("input");
        try (Scanner scanner = new Scanner(new File(input))) {
            // ok: java-resource-leak-detector
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            URL url = new URL("https://example.com");
            // ok: java-resource-leak-detector
            try (InputStream is = url.openStream()) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    System.out.write(buffer, 0, bytesRead);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try (PrintWriter writer = new PrintWriter(new FileWriter("output.txt"))) {
            // ok: java-resource-leak-detector
            writer.println("Hello, world!");
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try (ServerSocket serverSocket = new ServerSocket(8080);
             Socket clientSocket = serverSocket.accept();
             BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {
            // ok: java-resource-leak-detector
            String inputLine = in.readLine();
            System.out.println("Received: " + inputLine);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            byte[] key = "0123456789abcdef".getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            // ok: java-resource-leak-detector
            try (FileInputStream fis = new FileInputStream("encrypted.data");
                 CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    System.out.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        Properties props = new Properties();
        // ok: java-resource-leak-detector
        try (FileInputStream configStream = new FileInputStream("config.properties")) {
            props.load(configStream);
            String value = props.getProperty("key");
            System.out.println("Value: " + value);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request) {
        String id = request.getParameter("id");
        // ok: java-resource-leak-detector
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
             ResultSet rs = pstmt.executeQuery()) {
            
            pstmt.setString(1, id);
            while (rs.next()) {
                System.out.println(rs.getString("name"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}