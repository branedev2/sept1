import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.nio.file.*;

public class DoSReadLineVulnerabilities {

    // True Positives (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String fileName = request.getParameter("file");
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            StringBuilder content = new StringBuilder();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        try {
            URL url = new URL(request.getParameter("url"));
            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
            List<String> lines = new ArrayList<>();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            InputStream inputStream = request.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                response.getWriter().println("Received: " + line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            Socket socket = new Socket("example.com", 80);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        try {
            String zipFileName = request.getParameter("zipfile");
            Process process = Runtime.getRuntime().exec("unzip -l " + zipFileName);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        try {
            String configFile = request.getParameter("config");
            FileInputStream fis = new FileInputStream(configFile);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
            Map<String, String> configMap = new HashMap<>();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("=", 2);
                if (parts.length == 2) {
                    configMap.put(parts[0], parts[1]);
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            Socket clientSocket = serverSocket.accept();
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                // Process client data
                System.out.println("Client sent: " + line);
            }
            reader.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        try {
            String logFile = request.getParameter("logfile");
            BufferedReader reader = new BufferedReader(new FileReader(logFile));
            List<String> errorLines = new ArrayList<>();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                if (line.contains("ERROR")) {
                    errorLines.add(line);
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        try {
            String dataFile = request.getParameter("datafile");
            BufferedReader reader = new BufferedReader(new FileReader(dataFile));
            int sum = 0;
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                try {
                    sum += Integer.parseInt(line.trim());
                } catch (NumberFormatException e) {
                    // Skip non-numeric lines
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        try {
            String csvFile = request.getParameter("csvfile");
            BufferedReader reader = new BufferedReader(new FileReader(csvFile));
            List<String[]> records = new ArrayList<>();
            String line;
            
            // Skip header
            reader.readLine();
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                records.add(line.split(","));
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            URL url = new URL("https://example.com/largefile.txt");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            Part filePart = request.getPart("uploadedFile");
            BufferedReader reader = new BufferedReader(new InputStreamReader(filePart.getInputStream()));
            StringBuilder fileContent = new StringBuilder();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                fileContent.append(line).append("\n");
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        try {
            String xmlFile = request.getParameter("xmlfile");
            BufferedReader reader = new BufferedReader(new FileReader(xmlFile));
            StringBuilder xmlContent = new StringBuilder();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                xmlContent.append(line);
            }
            reader.close();
            
            // Process XML content
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            Process process = Runtime.getRuntime().exec("netstat -a");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            List<String> connections = new ArrayList<>();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                connections.add(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        try {
            String jsonFile = request.getParameter("jsonfile");
            BufferedReader reader = new BufferedReader(new FileReader(jsonFile));
            StringBuilder jsonContent = new StringBuilder();
            String line;
            
            // ruleid: java-denial-of-service
            while ((line = reader.readLine()) != null) {
                jsonContent.append(line);
            }
            reader.close();
            
            // Parse JSON content
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Safe Code)

    public void good_case_1(HttpServletRequest request) {
        try {
            String fileName = request.getParameter("file");
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            StringBuilder content = new StringBuilder();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 10000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                content.append(line);
                lineCount++;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        try {
            URL url = new URL(request.getParameter("url"));
            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
            List<String> lines = new ArrayList<>();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 5000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                lines.add(line);
                lineCount++;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            InputStream inputStream = request.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            int lineCount = 0;
            final int MAX_LINES = 1000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                response.getWriter().println("Received: " + line);
                lineCount++;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            Socket socket = new Socket("example.com", 80);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line;
            int lineCount = 0;
            final int MAX_LINES = 2000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                System.out.println(line);
                lineCount++;
            }
            reader.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request) {
        try {
            String zipFileName = request.getParameter("zipfile");
            Process process = Runtime.getRuntime().exec("unzip -l " + zipFileName);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            // ok: java-denial-of-service
            List<String> lines = reader.lines().limit(500).collect(java.util.stream.Collectors.toList());
            reader.close();
            
            for (String line : lines) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        try {
            String configFile = request.getParameter("config");
            
            // ok: java-denial-of-service
            List<String> allLines = Files.readAllLines(Paths.get(configFile));
            
            Map<String, String> configMap = new HashMap<>();
            for (String line : allLines) {
                String[] parts = line.split("=", 2);
                if (parts.length == 2) {
                    configMap.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            Socket clientSocket = serverSocket.accept();
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String line;
            int lineCount = 0;
            final int MAX_LINES = 100;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                // Process client data
                System.out.println("Client sent: " + line);
                lineCount++;
            }
            reader.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request) {
        try {
            String logFile = request.getParameter("logfile");
            
            // ok: java-denial-of-service
            List<String> errorLines = Files.lines(Paths.get(logFile))
                .filter(line -> line.contains("ERROR"))
                .limit(10000)
                .collect(java.util.stream.Collectors.toList());
                
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(HttpServletRequest request) {
        try {
            String dataFile = request.getParameter("datafile");
            BufferedReader reader = new BufferedReader(new FileReader(dataFile));
            int sum = 0;
            String line;
            int lineCount = 0;
            final int MAX_LINES = 10000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                try {
                    sum += Integer.parseInt(line.trim());
                } catch (NumberFormatException e) {
                    // Skip non-numeric lines
                }
                lineCount++;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        try {
            String csvFile = request.getParameter("csvfile");
            
            // ok: java-denial-of-service
            try (BufferedReader reader = new BufferedReader(new FileReader(csvFile))) {
                // Skip header
                reader.readLine();
                
                List<String[]> records = reader.lines()
                    .limit(5000)
                    .map(line -> line.split(","))
                    .collect(java.util.stream.Collectors.toList());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            URL url = new URL("https://example.com/largefile.txt");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // Set timeout to prevent hanging
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 10000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                response.append(line).append("\n");
                lineCount++;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            Part filePart = request.getPart("uploadedFile");
            
            // Check file size before processing
            if (filePart.getSize() > 10 * 1024 * 1024) { // 10MB limit
                throw new IllegalArgumentException("File too large");
            }
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(filePart.getInputStream()));
            StringBuilder fileContent = new StringBuilder();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 5000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                fileContent.append(line).append("\n");
                lineCount++;
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(HttpServletRequest request) {
        try {
            String xmlFile = request.getParameter("xmlfile");
            
            // ok: java-denial-of-service
            String xmlContent = Files.lines(Paths.get(xmlFile))
                .limit(10000)
                .collect(java.util.stream.Collectors.joining());
            
            // Process XML content
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            Process process = Runtime.getRuntime().exec("netstat -a");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            // ok: java-denial-of-service
            List<String> connections = reader.lines()
                .limit(1000)
                .collect(java.util.stream.Collectors.toList());
                
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request) {
        try {
            String jsonFile = request.getParameter("jsonfile");
            File file = new File(jsonFile);
            
            // Check file size before processing
            if (file.length() > 5 * 1024 * 1024) { // 5MB limit
                throw new IllegalArgumentException("JSON file too large");
            }
            
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuilder jsonContent = new StringBuilder();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 50000;
            
            // ok: java-denial-of-service
            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                jsonContent.append(line);
                lineCount++;
            }
            reader.close();
            
            // Parse JSON content
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}