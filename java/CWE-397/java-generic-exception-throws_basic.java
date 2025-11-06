import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;

public class GenericExceptionThrowsExamples {

    // True Positive Examples (Bad Cases)

// {fact rule=do-not-catch-and-throw-exception@v1.0 defects=1}
    public void bad_case_1() throws Exception {
        // ruleid: java-generic-exception-throws
        throw new Exception("Something went wrong"); // Throwing generic exception
    }

    public String bad_case_2(String filePath) throws Exception {
        File file = new File(filePath);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return new String(data, "UTF-8");
        } catch (IOException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Error reading file: " + e.getMessage());
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    // Ignoring close exception
                }
            }
        }
    }

    public Connection bad_case_3(String url, String username, String password) throws Exception {
        try {
            return DriverManager.getConnection(url, username, password);
        } catch (SQLException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Database connection failed", e);
        }
    }

    public void bad_case_4(Future<String> future) throws Exception {
        try {
            String result = future.get();
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Failed to get result from future", e);
        }
    }

    public void bad_case_5(String xmlFilePath) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new File(xmlFilePath));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("XML parsing failed", e);
        }
    }

    public int bad_case_6(String numberStr) throws Exception {
        try {
            return Integer.parseInt(numberStr);
        } catch (NumberFormatException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Invalid number format", e);
        }
    }

    public void bad_case_7(List<String> list, int index) throws Exception {
        try {
            String item = list.get(index);
            System.out.println("Item: " + item);
        } catch (IndexOutOfBoundsException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Index out of bounds", e);
        }
    }

    public void bad_case_8(Object obj) throws Exception {
        if (obj == null) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Object cannot be null");
        }
        System.out.println(obj.toString());
    }

    public void bad_case_9(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                // ruleid: java-generic-exception-throws
                throw new Exception("HTTP request failed with response code: " + responseCode);
            }
        } catch (IOException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("HTTP request failed", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public void bad_case_10(String[] args) throws Exception {
        if (args.length < 2) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Insufficient arguments provided");
        }
        System.out.println("Processing arguments: " + args[0] + ", " + args[1]);
    }

    public void bad_case_11(int value) throws Exception {
        switch (value) {
            case 1:
                System.out.println("One");
                break;
            case 2:
                System.out.println("Two");
                break;
            default:
                // ruleid: java-generic-exception-throws
                throw new Exception("Unsupported value: " + value);
        }
    }

    public List<String> bad_case_12(String[] items) throws Exception {
        List<String> result = new ArrayList<>();
        for (String item : items) {
            if (item == null || item.isEmpty()) {
                // ruleid: java-generic-exception-throws
                throw new Exception("Empty or null item found");
            }
            result.add(item.toUpperCase());
        }
        return result;
    }

    public void bad_case_13(String input) throws Exception {
        if (input.length() < 8) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Input must be at least 8 characters long");
        }
        System.out.println("Input is valid: " + input);
    }

    public void bad_case_14() throws Exception {
        Runtime runtime = Runtime.getRuntime();
        try {
            Process process = runtime.exec("ls -la");
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                // ruleid: java-generic-exception-throws
                throw new Exception("Command execution failed with exit code: " + exitCode);
            }
        } catch (IOException | InterruptedException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Command execution error", e);
        }
    }

    public void bad_case_15(String className) throws Exception {
        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            System.out.println("Created instance of: " + instance.getClass().getName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            // ruleid: java-generic-exception-throws
            throw new Exception("Failed to create instance of class: " + className, e);
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1() throws IOException {
        // ok: java-generic-exception-throws
        throw new IOException("File operation failed"); // Throwing specific exception
    }

    public String good_case_2(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return new String(data, "UTF-8");
        } catch (IOException e) {
            // ok: java-generic-exception-throws
            throw new IOException("Error reading file: " + e.getMessage(), e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    // Ignoring close exception
                }
            }
        }
    }

    public Connection good_case_3(String url, String username, String password) throws SQLException {
        try {
            return DriverManager.getConnection(url, username, password);
        } catch (SQLException e) {
            // ok: java-generic-exception-throws
            throw new SQLException("Database connection failed", e);
        }
    }

    public void good_case_4(Future<String> future) throws InterruptedException, ExecutionException {
        try {
            String result = future.get();
            System.out.println("Result: " + result);
        } catch (InterruptedException e) {
            // ok: java-generic-exception-throws
            throw new InterruptedException("Operation was interrupted: " + e.getMessage());
        } catch (ExecutionException e) {
            // ok: java-generic-exception-throws
            throw new ExecutionException("Execution failed", e);
        }
    }

    public void good_case_5(String xmlFilePath) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new File(xmlFilePath));
        } catch (ParserConfigurationException e) {
            // ok: java-generic-exception-throws
            throw new ParserConfigurationException("Parser configuration error: " + e.getMessage());
        } catch (SAXException e) {
            // ok: java-generic-exception-throws
            throw new SAXException("XML parsing error", e);
        } catch (IOException e) {
            // ok: java-generic-exception-throws
            throw new IOException("File read error", e);
        }
    }

    public int good_case_6(String numberStr) throws IllegalArgumentException {
        try {
            return Integer.parseInt(numberStr);
        } catch (NumberFormatException e) {
            // ok: java-generic-exception-throws
            throw new IllegalArgumentException("Invalid number format: " + numberStr, e);
        }
    }

    public void good_case_7(List<String> list, int index) throws IndexOutOfBoundsException {
        try {
            String item = list.get(index);
            System.out.println("Item: " + item);
        } catch (IndexOutOfBoundsException e) {
            // ok: java-generic-exception-throws
            throw new IndexOutOfBoundsException("Index " + index + " is out of bounds for list of size " + list.size());
        }
    }

    public void good_case_8(Object obj) throws NullPointerException {
        if (obj == null) {
            // ok: java-generic-exception-throws
            throw new NullPointerException("Object cannot be null");
        }
        System.out.println(obj.toString());
    }

    public void good_case_9(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                // ok: java-generic-exception-throws
                throw new IOException("HTTP request failed with response code: " + responseCode);
            }
        } catch (IOException e) {
            // ok: java-generic-exception-throws
            throw new IOException("HTTP request failed: " + e.getMessage(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public void good_case_10(String[] args) throws IllegalArgumentException {
        if (args.length < 2) {
            // ok: java-generic-exception-throws
            throw new IllegalArgumentException("Insufficient arguments provided. Expected at least 2, got " + args.length);
        }
        System.out.println("Processing arguments: " + args[0] + ", " + args[1]);
    }

    public void good_case_11(int value) throws IllegalArgumentException {
        switch (value) {
            case 1:
                System.out.println("One");
                break;
            case 2:
                System.out.println("Two");
                break;
            default:
                // ok: java-generic-exception-throws
                throw new IllegalArgumentException("Unsupported value: " + value);
        }
    }

    public List<String> good_case_12(String[] items) throws IllegalArgumentException {
        List<String> result = new ArrayList<>();
        for (String item : items) {
            if (item == null || item.isEmpty()) {
                // ok: java-generic-exception-throws
                throw new IllegalArgumentException("Empty or null item found");
            }
            result.add(item.toUpperCase());
        }
        return result;
    }

    public void good_case_13(String input) throws IllegalArgumentException {
        if (input.length() < 8) {
            // ok: java-generic-exception-throws
            throw new IllegalArgumentException("Input must be at least 8 characters long, got " + input.length());
        }
        System.out.println("Input is valid: " + input);
    }

    public void good_case_14() throws IOException, InterruptedException {
        Runtime runtime = Runtime.getRuntime();
        try {
            Process process = runtime.exec("ls -la");
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                // ok: java-generic-exception-throws
                throw new IOException("Command execution failed with exit code: " + exitCode);
            }
        } catch (IOException e) {
            // ok: java-generic-exception-throws
            throw new IOException("Command execution error: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            // ok: java-generic-exception-throws
            throw new InterruptedException("Command execution was interrupted");
        }
    }

    public void good_case_15(String className) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            System.out.println("Created instance of: " + instance.getClass().getName());
        } catch (ClassNotFoundException e) {
            // ok: java-generic-exception-throws
            throw new ClassNotFoundException("Class not found: " + className);
        } catch (InstantiationException e) {
            // ok: java-generic-exception-throws
            throw new InstantiationException("Cannot instantiate class: " + e.getMessage());
        } catch (IllegalAccessException e) {
            // ok: java-generic-exception-throws
            throw new IllegalAccessException("Cannot access class constructor: " + e.getMessage());
        }
    }
}
// {/fact}