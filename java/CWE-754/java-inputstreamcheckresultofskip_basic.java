import java.io.*;
import java.net.URL;
import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.GZIPInputStream;

public class InputStreamSkipExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=missing-check-on-method-output@v1.0 defects=1}
    public void bad_case_1() {
        try (FileInputStream fis = new FileInputStream("data.bin")) {
            // ruleid: java-inputstreamcheckresultofskip
            fis.skip(10); // Not checking the result of skip()
            byte[] buffer = new byte[100];
            fis.read(buffer);
            processData(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            InputStream is = new URL("https://example.com/data").openStream();
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(5); // Skip header without checking result
            byte[] data = is.readAllBytes();
            is.close();
            processData(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream("config.dat"))) {
            // ruleid: java-inputstreamcheckresultofskip
            bis.skip(24); // Skip file header without checking
            int value = bis.read();
            System.out.println("Config value: " + value);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL("https://api.example.com/data").openConnection();
            InputStream is = conn.getInputStream();
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(2); // Skip first two bytes without checking
            byte[] response = is.readAllBytes();
            is.close();
            processData(response);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try (DataInputStream dis = new DataInputStream(new FileInputStream("records.dat"))) {
            // Skip to the 10th record
            // ruleid: java-inputstreamcheckresultofskip
            dis.skip(9 * 16); // Each record is 16 bytes, not checking result
            int id = dis.readInt();
            String name = dis.readUTF();
            System.out.println("ID: " + id + ", Name: " + name);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            InputStream is = getClass().getResourceAsStream("/data.bin");
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(100); // Skip first 100 bytes without checking
            byte[] buffer = new byte[50];
            is.read(buffer);
            is.close();
            processData(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try (GZIPInputStream gzis = new GZIPInputStream(new FileInputStream("data.gz"))) {
            // ruleid: java-inputstreamcheckresultofskip
            gzis.skip(16); // Skip header without checking
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                System.out.write(buffer, 0, len);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            PipedInputStream pis = new PipedInputStream();
            PipedOutputStream pos = new PipedOutputStream(pis);
            
            // Write some data to the pipe
            new Thread(() -> {
                try {
                    pos.write(new byte[100]);
                    pos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            
            // ruleid: java-inputstreamcheckresultofskip
            pis.skip(10); // Skip without checking
            byte[] data = pis.readAllBytes();
            pis.close();
            processData(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            InputStream is = Files.newInputStream(Paths.get("large_file.dat"));
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(1024 * 1024); // Skip 1MB without checking
            byte[] buffer = new byte[4096];
            int bytesRead = is.read(buffer);
            is.close();
            if (bytesRead > 0) {
                processData(buffer);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try (InputStream is = new ByteArrayInputStream(new byte[1000])) {
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(500); // Skip half the array without checking
            int b = is.read();
            System.out.println("Byte at position 501: " + b);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            RandomAccessFile raf = new RandomAccessFile("data.bin", "r");
            InputStream is = new FileInputStream(raf.getFD());
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(raf.length() / 2); // Skip to middle without checking
            byte[] buffer = new byte[100];
            is.read(buffer);
            is.close();
            raf.close();
            processData(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            SequenceInputStream sis = new SequenceInputStream(
                new FileInputStream("part1.dat"),
                new FileInputStream("part2.dat")
            );
            // ruleid: java-inputstreamcheckresultofskip
            sis.skip(20); // Skip without checking
            byte[] data = sis.readAllBytes();
            sis.close();
            processData(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            InputStream is = new URL("https://example.com/large_file").openStream();
            // Attempt to skip a large amount
            long toSkip = 1024L * 1024L * 100L; // 100MB
            // ruleid: java-inputstreamcheckresultofskip
            is.skip(toSkip); // Not checking if all bytes were skipped
            byte[] buffer = new byte[1024];
            is.read(buffer);
            is.close();
            processData(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("text.txt")))) {
            // Skip first line
            // ruleid: java-inputstreamcheckresultofskip
            br.skip(br.readLine().length() + 1); // Skip without checking
            String secondLine = br.readLine();
            System.out.println("Second line: " + secondLine);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Create a custom FilterInputStream
            InputStream baseStream = new FileInputStream("data.bin");
            FilterInputStream fis = new FilterInputStream(baseStream) {};
            
            // ruleid: java-inputstreamcheckresultofskip
            fis.skip(50); // Skip without checking
            byte[] data = fis.readAllBytes();
            fis.close();
            processData(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        try (FileInputStream fis = new FileInputStream("data.bin")) {
            long bytesToSkip = 10;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = fis.skip(bytesToSkip);
            if (bytesSkipped != bytesToSkip) {
                System.err.println("Could not skip requested bytes");
                return;
            }
            byte[] buffer = new byte[100];
            fis.read(buffer);
            processData(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            InputStream is = new URL("https://example.com/data").openStream();
            long bytesToSkip = 5;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = 0;
            while (bytesSkipped < bytesToSkip) {
                long result = is.skip(bytesToSkip - bytesSkipped);
                if (result <= 0) {
                    break; // Cannot skip any more
                }
                bytesSkipped += result;
            }
            if (bytesSkipped == bytesToSkip) {
                byte[] data = is.readAllBytes();
                processData(data);
            }
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream("config.dat"))) {
            long bytesToSkip = 24;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = bis.skip(bytesToSkip);
            if (bytesSkipped == bytesToSkip) {
                int value = bis.read();
                System.out.println("Config value: " + value);
            } else {
                System.err.println("Could not skip header, only skipped " + bytesSkipped + " bytes");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL("https://api.example.com/data").openConnection();
            InputStream is = conn.getInputStream();
            long bytesToSkip = 2;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = is.skip(bytesToSkip);
            if (bytesSkipped == bytesToSkip) {
                byte[] response = is.readAllBytes();
                processData(response);
            } else {
                System.err.println("Failed to skip header bytes");
            }
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try (DataInputStream dis = new DataInputStream(new FileInputStream("records.dat"))) {
            long recordSize = 16; // Each record is 16 bytes
            long recordsToSkip = 9;
            long bytesToSkip = recordsToSkip * recordSize;
            
            // ok: java-inputstreamcheckresultofskip
            long totalSkipped = 0;
            while (totalSkipped < bytesToSkip) {
                long skipped = dis.skip(bytesToSkip - totalSkipped);
                if (skipped <= 0) {
                    throw new IOException("Failed to skip to desired record");
                }
                totalSkipped += skipped;
            }
            
            int id = dis.readInt();
            String name = dis.readUTF();
            System.out.println("ID: " + id + ", Name: " + name);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            InputStream is = getClass().getResourceAsStream("/data.bin");
            long bytesToSkip = 100;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = skipFully(is, bytesToSkip);
            if (bytesSkipped == bytesToSkip) {
                byte[] buffer = new byte[50];
                is.read(buffer);
                processData(buffer);
            } else {
                System.err.println("Could not skip all requested bytes");
            }
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try (GZIPInputStream gzis = new GZIPInputStream(new FileInputStream("data.gz"))) {
            long bytesToSkip = 16;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = 0;
            while (bytesSkipped < bytesToSkip) {
                long result = gzis.skip(bytesToSkip - bytesSkipped);
                if (result <= 0) {
                    System.err.println("Failed to skip all requested bytes");
                    return;
                }
                bytesSkipped += result;
            }
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                System.out.write(buffer, 0, len);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            PipedInputStream pis = new PipedInputStream();
            PipedOutputStream pos = new PipedOutputStream(pis);
            
            // Write some data to the pipe
            new Thread(() -> {
                try {
                    pos.write(new byte[100]);
                    pos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            
            long bytesToSkip = 10;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = pis.skip(bytesToSkip);
            if (bytesSkipped == bytesToSkip) {
                byte[] data = pis.readAllBytes();
                processData(data);
            } else {
                System.err.println("Could not skip " + bytesToSkip + " bytes, only skipped " + bytesSkipped);
            }
            pis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            InputStream is = Files.newInputStream(Paths.get("large_file.dat"));
            long bytesToSkip = 1024 * 1024; // 1MB
            // ok: java-inputstreamcheckresultofskip
            long totalSkipped = 0;
            while (totalSkipped < bytesToSkip) {
                long skipped = is.skip(bytesToSkip - totalSkipped);
                if (skipped <= 0) {
                    break; // Cannot skip any more
                }
                totalSkipped += skipped;
            }
            
            if (totalSkipped == bytesToSkip) {
                byte[] buffer = new byte[4096];
                int bytesRead = is.read(buffer);
                if (bytesRead > 0) {
                    processData(buffer);
                }
            } else {
                System.err.println("Could not skip all requested bytes");
            }
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try (InputStream is = new ByteArrayInputStream(new byte[1000])) {
            long bytesToSkip = 500;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = is.skip(bytesToSkip);
            if (bytesSkipped == bytesToSkip) {
                int b = is.read();
                System.out.println("Byte at position 501: " + b);
            } else {
                System.err.println("Failed to skip to position 501");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            RandomAccessFile raf = new RandomAccessFile("data.bin", "r");
            InputStream is = new FileInputStream(raf.getFD());
            long bytesToSkip = raf.length() / 2;
            
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = 0;
            while (bytesSkipped < bytesToSkip) {
                long result = is.skip(bytesToSkip - bytesSkipped);
                if (result <= 0) {
                    System.err.println("Cannot skip any more bytes");
                    break;
                }
                bytesSkipped += result;
            }
            
            if (bytesSkipped == bytesToSkip) {
                byte[] buffer = new byte[100];
                is.read(buffer);
                processData(buffer);
            }
            is.close();
            raf.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            SequenceInputStream sis = new SequenceInputStream(
                new FileInputStream("part1.dat"),
                new FileInputStream("part2.dat")
            );
            long bytesToSkip = 20;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = skipFully(sis, bytesToSkip);
            if (bytesSkipped == bytesToSkip) {
                byte[] data = sis.readAllBytes();
                processData(data);
            } else {
                System.err.println("Could not skip all requested bytes");
            }
            sis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            InputStream is = new URL("https://example.com/large_file").openStream();
            long toSkip = 1024L * 1024L * 100L; // 100MB
            
            // ok: java-inputstreamcheckresultofskip
            long totalSkipped = 0;
            long skipped;
            while (totalSkipped < toSkip && (skipped = is.skip(toSkip - totalSkipped)) > 0) {
                totalSkipped += skipped;
            }
            
            if (totalSkipped == toSkip) {
                System.out.println("Successfully skipped 100MB");
                byte[] buffer = new byte[1024];
                is.read(buffer);
                processData(buffer);
            } else {
                System.err.println("Could only skip " + totalSkipped + " bytes out of " + toSkip);
            }
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("text.txt")))) {
            String firstLine = br.readLine();
            if (firstLine != null) {
                long bytesToSkip = 1; // Skip the newline character
                // ok: java-inputstreamcheckresultofskip
                long bytesSkipped = br.skip(bytesToSkip);
                if (bytesSkipped == bytesToSkip) {
                    String secondLine = br.readLine();
                    System.out.println("Second line: " + secondLine);
                } else {
                    System.err.println("Could not skip newline character");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // Create a custom FilterInputStream
            InputStream baseStream = new FileInputStream("data.bin");
            FilterInputStream fis = new FilterInputStream(baseStream) {};
            
            long bytesToSkip = 50;
            // ok: java-inputstreamcheckresultofskip
            long bytesSkipped = 0;
            while (bytesSkipped < bytesToSkip) {
                long result = fis.skip(bytesToSkip - bytesSkipped);
                if (result <= 0) {
                    System.err.println("Cannot skip any more bytes");
                    break;
                }
                bytesSkipped += result;
            }
            
            if (bytesSkipped == bytesToSkip) {
                byte[] data = fis.readAllBytes();
                processData(data);
            }
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Helper method for skipping bytes fully
    private long skipFully(InputStream is, long bytesToSkip) throws IOException {
        long totalSkipped = 0;
        while (totalSkipped < bytesToSkip) {
            long skipped = is.skip(bytesToSkip - totalSkipped);
            if (skipped <= 0) {
                break; // Cannot skip any more
            }
            totalSkipped += skipped;
        }
        return totalSkipped;
    }

    // Helper method to process data
    private void processData(byte[] data) {
        // Process the data
        System.out.println("Processing " + data.length + " bytes of data");
    }
}
// {/fact}