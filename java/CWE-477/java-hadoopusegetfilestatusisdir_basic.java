import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.conf.Configuration;
import java.io.IOException;

public class HadoopFileSystemUsageExamples {

    // True Positive Examples (Vulnerable/Deprecated Code)

// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.isDirectory(path);
        
        if (isDir) {
            System.out.println("Path is a directory");
        }
    }

    public void bad_case_2() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path inputPath = new Path("/user/hadoop/input");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (fs.isDirectory(inputPath)) {
            System.out.println("Processing directory: " + inputPath);
        }
    }

    public void bad_case_3() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path outputPath = new Path("/user/hadoop/output");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.isDirectory(outputPath);
        
        if (!isDir) {
            fs.mkdirs(outputPath);
        }
    }

    public void bad_case_4() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path[] paths = {
            new Path("/user/hadoop/dir1"),
            new Path("/user/hadoop/dir2")
        };
        
        for (Path p : paths) {
            // ruleid: java-hadoopusegetfilestatusisdir
            if (fs.isDirectory(p)) {
                System.out.println(p + " is a directory");
            }
        }
    }

    public void bad_case_5() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path logDir = new Path("/user/hadoop/logs");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isLogDirExists = fs.exists(logDir) && fs.isDirectory(logDir);
        
        if (!isLogDirExists) {
            fs.mkdirs(logDir);
        }
    }

    public void bad_case_6() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path dataPath = new Path("/user/hadoop/data");
        
        try {
            // ruleid: java-hadoopusegetfilestatusisdir
            if (!fs.isDirectory(dataPath)) {
                throw new IllegalArgumentException("Data path must be a directory");
            }
        } catch (IOException e) {
            System.err.println("Error checking path: " + e.getMessage());
        }
    }

    public void bad_case_7() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path configPath = new Path("/user/hadoop/config");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.isDirectory(configPath);
        boolean exists = fs.exists(configPath);
        
        if (exists && isDir) {
            System.out.println("Config directory exists");
        }
    }

    public void bad_case_8() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path tempDir = new Path("/tmp/hadoop");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (fs.isDirectory(tempDir)) {
            fs.delete(tempDir, true);
            fs.mkdirs(tempDir);
        }
    }

    public void bad_case_9() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean result = checkIfDirectory(fs, path);
        
        System.out.println("Is directory: " + result);
    }
    
    private boolean checkIfDirectory(FileSystem fs, Path path) throws IOException {
        // ruleid: java-hadoopusegetfilestatusisdir
        return fs.isDirectory(path);
    }

    public void bad_case_10() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path inputDir = new Path("/user/hadoop/input");
        Path outputDir = new Path("/user/hadoop/output");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isInputDir = fs.isDirectory(inputDir);
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isOutputDir = fs.isDirectory(outputDir);
        
        if (isInputDir && !isOutputDir) {
            fs.mkdirs(outputDir);
        }
    }

    public void bad_case_11() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        String pathStr = path.toString();
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.isDirectory(new Path(pathStr));
        
        System.out.println("Is directory: " + isDir);
    }

    public void bad_case_12() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path baseDir = new Path("/user/hadoop");
        
        for (int i = 0; i < 3; i++) {
            Path subDir = new Path(baseDir, "dir" + i);
            // ruleid: java-hadoopusegetfilestatusisdir
            if (!fs.isDirectory(subDir)) {
                fs.mkdirs(subDir);
            }
        }
    }

    public void bad_case_13() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        try {
            // ruleid: java-hadoopusegetfilestatusisdir
            boolean isDir = fs.isDirectory(path);
            System.out.println("Is directory: " + isDir);
        } finally {
            fs.close();
        }
    }

    public void bad_case_14() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.isDirectory(path);
        
        switch (isDir ? 1 : 0) {
            case 1:
                System.out.println("It's a directory");
                break;
            case 0:
                System.out.println("It's a file");
                break;
        }
    }

    public void bad_case_15() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path1 = new Path("/user/hadoop/dir1");
        Path path2 = new Path("/user/hadoop/dir2");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir1 = fs.isDirectory(path1);
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir2 = fs.isDirectory(path2);
        
        if (isDir1 && isDir2) {
            System.out.println("Both are directories");
        }
    }

    // True Negative Examples (Safe/Recommended Code)

    public void good_case_1() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.getFileStatus(path).isDirectory();
        
        if (isDir) {
            System.out.println("Path is a directory");
        }
    }

    public void good_case_2() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path inputPath = new Path("/user/hadoop/input");
        
        // ok: java-hadoopusegetfilestatusisdir
        if (fs.getFileStatus(inputPath).isDirectory()) {
            System.out.println("Processing directory: " + inputPath);
        }
    }

    public void good_case_3() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path outputPath = new Path("/user/hadoop/output");
        
        // ok: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.getFileStatus(outputPath).isDirectory();
        
        if (!isDir) {
            fs.mkdirs(outputPath);
        }
    }

    public void good_case_4() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path[] paths = {
            new Path("/user/hadoop/dir1"),
            new Path("/user/hadoop/dir2")
        };
        
        for (Path p : paths) {
            // ok: java-hadoopusegetfilestatusisdir
            if (fs.getFileStatus(p).isDirectory()) {
                System.out.println(p + " is a directory");
            }
        }
    }

    public void good_case_5() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path logDir = new Path("/user/hadoop/logs");
        
        boolean exists = fs.exists(logDir);
        // ok: java-hadoopusegetfilestatusisdir
        boolean isLogDirExists = exists && fs.getFileStatus(logDir).isDirectory();
        
        if (!isLogDirExists) {
            fs.mkdirs(logDir);
        }
    }

    public void good_case_6() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path dataPath = new Path("/user/hadoop/data");
        
        try {
            // ok: java-hadoopusegetfilestatusisdir
            if (!fs.getFileStatus(dataPath).isDirectory()) {
                throw new IllegalArgumentException("Data path must be a directory");
            }
        } catch (IOException e) {
            System.err.println("Error checking path: " + e.getMessage());
        }
    }

    public void good_case_7() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path configPath = new Path("/user/hadoop/config");
        
        boolean exists = fs.exists(configPath);
        // ok: java-hadoopusegetfilestatusisdir
        boolean isDir = exists && fs.getFileStatus(configPath).isDirectory();
        
        if (exists && isDir) {
            System.out.println("Config directory exists");
        }
    }

    public void good_case_8() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path tempDir = new Path("/tmp/hadoop");
        
        if (fs.exists(tempDir)) {
            // ok: java-hadoopusegetfilestatusisdir
            if (fs.getFileStatus(tempDir).isDirectory()) {
                fs.delete(tempDir, true);
                fs.mkdirs(tempDir);
            }
        }
    }

    public void good_case_9() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        boolean result = checkIfDirectorySafe(fs, path);
        
        System.out.println("Is directory: " + result);
    }
    
    private boolean checkIfDirectorySafe(FileSystem fs, Path path) throws IOException {
        // ok: java-hadoopusegetfilestatusisdir
        return fs.getFileStatus(path).isDirectory();
    }

    public void good_case_10() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path inputDir = new Path("/user/hadoop/input");
        Path outputDir = new Path("/user/hadoop/output");
        
        // ok: java-hadoopusegetfilestatusisdir
        boolean isInputDir = fs.getFileStatus(inputDir).isDirectory();
        boolean isOutputDirExists = fs.exists(outputDir);
        boolean isOutputDir = false;
        
        if (isOutputDirExists) {
            // ok: java-hadoopusegetfilestatusisdir
            isOutputDir = fs.getFileStatus(outputDir).isDirectory();
        }
        
        if (isInputDir && !isOutputDir) {
            fs.mkdirs(outputDir);
        }
    }

    public void good_case_11() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = fs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        System.out.println("Is directory: " + isDir);
    }

    public void good_case_12() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path baseDir = new Path("/user/hadoop");
        
        for (int i = 0; i < 3; i++) {
            Path subDir = new Path(baseDir, "dir" + i);
            boolean exists = fs.exists(subDir);
            
            if (!exists || (exists && 
                // ok: java-hadoopusegetfilestatusisdir
                !fs.getFileStatus(subDir).isDirectory())) {
                fs.mkdirs(subDir);
            }
        }
    }

    public void good_case_13() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        try {
            // ok: java-hadoopusegetfilestatusisdir
            FileStatus status = fs.getFileStatus(path);
            boolean isDir = status.isDirectory();
            System.out.println("Is directory: " + isDir);
        } finally {
            fs.close();
        }
    }

    public void good_case_14() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/hadoop/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = fs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        switch (isDir ? 1 : 0) {
            case 1:
                System.out.println("It's a directory");
                break;
            case 0:
                System.out.println("It's a file");
                break;
        }
    }

    public void good_case_15() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path1 = new Path("/user/hadoop/dir1");
        Path path2 = new Path("/user/hadoop/dir2");
        
        // ok: java-hadoopusegetfilestatusisdir
        boolean isDir1 = fs.getFileStatus(path1).isDirectory();
        // ok: java-hadoopusegetfilestatusisdir
        boolean isDir2 = fs.getFileStatus(path2).isDirectory();
        
        if (isDir1 && isDir2) {
            System.out.println("Both are directories");
        }
    }
}
// {/fact}