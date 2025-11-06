import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.Level;

public class HadoopRenameExamples {
    private static final Logger logger = Logger.getLogger(HadoopRenameExamples.class.getName());
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/file1.txt");
        Path dst = new Path("/user/hadoop/file2.txt");
        
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(src, dst); // Not checking the return value
        
        // Continue with operation assuming rename was successful
        System.out.println("File renamed successfully");
    }
    
    public void bad_case_2() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/olddir");
        Path dst = new Path("/user/hadoop/newdir");
        
        try {
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst); // Return value ignored
            System.out.println("Directory renamed");
        } catch (IOException e) {
            System.err.println("Error during rename: " + e.getMessage());
        }
    }
    
    public void bad_case_3() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path[] srcPaths = {
            new Path("/user/hadoop/file1.txt"),
            new Path("/user/hadoop/file2.txt")
        };
        
        for (Path src : srcPaths) {
            Path dst = new Path(src.toString() + ".bak");
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst); // Not checking return value in loop
        }
    }
    
    public void bad_case_4() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/source.txt");
        Path dst = new Path("/user/hadoop/destination.txt");
        
        try {
            if (fs.exists(src)) {
                // ruleid: java-hadoopcheckresultoffilerename
                fs.rename(src, dst); // Checking existence but not rename result
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error occurred", e);
        }
    }
    
    public void bad_case_5() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/tmp/data.txt");
        Path dst = new Path("/archive/data.txt");
        
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(src, dst);
        fs.delete(src, false); // Attempting to delete source after rename without checking if rename succeeded
    }
    
    public void bad_case_6() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        
        // Nested method call, return value still ignored
        // ruleid: java-hadoopcheckresultoffilerename
        processPath(fs.rename(new Path("/data/input.txt"), new Path("/data/processed.txt")));
    }
    
    private void processPath(boolean ignored) {
        // Method doesn't use the return value
    }
    
    public void bad_case_7() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/user/hadoop/temp.txt");
        Path dst = new Path("/user/hadoop/final.txt");
        
        // Using in conditional but not checking the result
        if (fs.exists(src)) {
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst);
            logger.info("Rename operation completed");
        }
    }
    
    public void bad_case_8() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/original.txt");
        Path dst = new Path("/user/hadoop/renamed.txt");
        
        Runnable renameTask = () -> {
            try {
                // ruleid: java-hadoopcheckresultoffilerename
                fs.rename(src, dst); // Ignoring return value in lambda
            } catch (IOException e) {
                e.printStackTrace();
            }
        };
        
        new Thread(renameTask).start();
    }
    
    public void bad_case_9() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/user/hadoop/source_file.txt");
        Path dst = new Path("/user/hadoop/target_file.txt");
        
        // Using try-with-resources but still not checking return value
        try (FileSystem fileSystem = fs) {
            // ruleid: java-hadoopcheckresultoffilerename
            fileSystem.rename(src, dst);
            System.out.println("Operation completed");
        }
    }
    
    public void bad_case_10() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/data/logs/app.log");
        Path dst = new Path("/data/archived/app.log");
        
        // Multiple operations but no check on rename
        if (fs.exists(src) && !fs.exists(dst)) {
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst);
            fs.create(new Path("/data/logs/app.log")); // Creating new log file
        }
    }
    
    public void bad_case_11() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        String filename = "important_data.txt";
        Path src = new Path("/tmp/" + filename);
        Path dst = new Path("/secure/" + filename);
        
        // Using string concatenation but still not checking result
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(src, dst);
        logger.info("File " + filename + " has been processed");
    }
    
    public void bad_case_12() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/user/hadoop/config.xml");
        Path dst = new Path("/user/hadoop/config.xml.bak");
        
        // Checking file attributes but not rename result
        if (fs.getFileStatus(src).getLen() > 0) {
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst);
            System.out.println("Backup created");
        }
    }
    
    public void bad_case_13() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/data.csv");
        Path dst = new Path("/user/hadoop/processed/data.csv");
        
        // Using in a more complex condition but still not checking
        if (System.currentTimeMillis() % 2 == 0) {
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst);
        } else {
            System.out.println("Skipping rename operation");
        }
    }
    
    public void bad_case_14() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/tmp/hadoop_temp_file.txt");
        Path dst = new Path("/output/hadoop_final_file.txt");
        
        // Using with other filesystem operations but not checking rename
        if (fs.exists(src)) {
            // ruleid: java-hadoopcheckresultoffilerename
            fs.rename(src, dst);
            fs.setPermission(dst, new org.apache.hadoop.fs.permission.FsPermission("644"));
        }
    }
    
    public void bad_case_15() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/input.dat");
        Path intermediate = new Path("/user/hadoop/processing.dat");
        Path dst = new Path("/user/hadoop/output.dat");
        
        // Multiple renames without checking
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(src, intermediate);
        // Process the file...
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(intermediate, dst);
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/file1.txt");
        Path dst = new Path("/user/hadoop/file2.txt");
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = fs.rename(src, dst);
        if (success) {
            System.out.println("File renamed successfully");
        } else {
            System.out.println("Failed to rename file");
        }
    }
    
    public void good_case_2() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/olddir");
        Path dst = new Path("/user/hadoop/newdir");
        
        try {
            // ok: java-hadoopcheckresultoffilerename
            if (!fs.rename(src, dst)) {
                System.err.println("Rename operation failed");
                // Handle the failure case
            }
        } catch (IOException e) {
            System.err.println("Error during rename: " + e.getMessage());
        }
    }
    
    public void good_case_3() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path[] srcPaths = {
            new Path("/user/hadoop/file1.txt"),
            new Path("/user/hadoop/file2.txt")
        };
        
        for (Path src : srcPaths) {
            Path dst = new Path(src.toString() + ".bak");
            // ok: java-hadoopcheckresultoffilerename
            boolean renameSuccess = fs.rename(src, dst);
            if (!renameSuccess) {
                logger.warning("Failed to rename " + src + " to " + dst);
                // Handle the failure
            }
        }
    }
    
    public void good_case_4() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/source.txt");
        Path dst = new Path("/user/hadoop/destination.txt");
        
        try {
            if (fs.exists(src)) {
                // ok: java-hadoopcheckresultoffilerename
                if (fs.rename(src, dst)) {
                    logger.info("Rename successful");
                } else {
                    logger.warning("Rename failed");
                    // Handle failure
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error occurred", e);
        }
    }
    
    public void good_case_5() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/tmp/data.txt");
        Path dst = new Path("/archive/data.txt");
        
        // ok: java-hadoopcheckresultoffilerename
        boolean renameSuccess = fs.rename(src, dst);
        if (renameSuccess) {
            // Only delete source if rename was successful
            fs.delete(src, false);
        } else {
            logger.warning("Rename failed, not deleting source file");
        }
    }
    
    public void good_case_6() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/data/input.txt");
        Path dst = new Path("/data/processed.txt");
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = fs.rename(src, dst);
        processRenameResult(success);
    }
    
    private void processRenameResult(boolean success) {
        if (success) {
            logger.info("Rename operation succeeded");
        } else {
            logger.warning("Rename operation failed");
        }
    }
    
    public void good_case_7() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/user/hadoop/temp.txt");
        Path dst = new Path("/user/hadoop/final.txt");
        
        if (fs.exists(src)) {
            // ok: java-hadoopcheckresultoffilerename
            boolean renamed = fs.rename(src, dst);
            logger.info("Rename operation " + (renamed ? "succeeded" : "failed"));
            
            if (!renamed) {
                // Implement recovery logic
                logger.warning("Implementing recovery logic after failed rename");
            }
        }
    }
    
    public void good_case_8() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/original.txt");
        Path dst = new Path("/user/hadoop/renamed.txt");
        
        Runnable renameTask = () -> {
            try {
                // ok: java-hadoopcheckresultoffilerename
                boolean success = fs.rename(src, dst);
                if (!success) {
                    logger.warning("Rename failed in background thread");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        };
        
        new Thread(renameTask).start();
    }
    
    public void good_case_9() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/user/hadoop/source_file.txt");
        Path dst = new Path("/user/hadoop/target_file.txt");
        
        // Using try-with-resources and checking return value
        try (FileSystem fileSystem = fs) {
            // ok: java-hadoopcheckresultoffilerename
            if (!fileSystem.rename(src, dst)) {
                logger.warning("Rename operation failed");
                // Handle failure
            } else {
                System.out.println("Operation completed successfully");
            }
        }
    }
    
    public void good_case_10() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/data/logs/app.log");
        Path dst = new Path("/data/archived/app.log");
        
        // Multiple operations with proper check on rename
        if (fs.exists(src) && !fs.exists(dst)) {
            // ok: java-hadoopcheckresultoffilerename
            boolean renamed = fs.rename(src, dst);
            if (renamed) {
                fs.create(new Path("/data/logs/app.log")); // Creating new log file
            } else {
                logger.warning("Failed to archive log file");
            }
        }
    }
    
    public void good_case_11() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        String filename = "important_data.txt";
        Path src = new Path("/tmp/" + filename);
        Path dst = new Path("/secure/" + filename);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = fs.rename(src, dst);
        if (success) {
            logger.info("File " + filename + " has been moved to secure location");
        } else {
            logger.warning("Failed to move file " + filename + " to secure location");
            // Implement recovery logic
        }
    }
    
    public void good_case_12() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/user/hadoop/config.xml");
        Path dst = new Path("/user/hadoop/config.xml.bak");
        
        // Checking file attributes and rename result
        if (fs.getFileStatus(src).getLen() > 0) {
            // ok: java-hadoopcheckresultoffilerename
            if (fs.rename(src, dst)) {
                System.out.println("Backup created successfully");
            } else {
                System.out.println("Failed to create backup");
                // Handle failure
            }
        }
    }
    
    public void good_case_13() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/data.csv");
        Path dst = new Path("/user/hadoop/processed/data.csv");
        
        // Using in a more complex condition and checking result
        if (System.currentTimeMillis() % 2 == 0) {
            // ok: java-hadoopcheckresultoffilerename
            boolean success = fs.rename(src, dst);
            if (success) {
                System.out.println("Rename operation succeeded");
            } else {
                System.out.println("Rename operation failed");
                // Handle failure
            }
        } else {
            System.out.println("Skipping rename operation");
        }
    }
    
    public void good_case_14() throws IOException {
        FileSystem fs = FileSystem.get(new Configuration());
        Path src = new Path("/tmp/hadoop_temp_file.txt");
        Path dst = new Path("/output/hadoop_final_file.txt");
        
        // Using with other filesystem operations and checking rename
        if (fs.exists(src)) {
            // ok: java-hadoopcheckresultoffilerename
            boolean renamed = fs.rename(src, dst);
            if (renamed) {
                fs.setPermission(dst, new org.apache.hadoop.fs.permission.FsPermission("644"));
            } else {
                logger.warning("Failed to move file, not setting permissions");
                // Handle failure
            }
        }
    }
    
    public void good_case_15() throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path("/user/hadoop/input.dat");
        Path intermediate = new Path("/user/hadoop/processing.dat");
        Path dst = new Path("/user/hadoop/output.dat");
        
        // Multiple renames with proper checking
        // ok: java-hadoopcheckresultoffilerename
        boolean firstRename = fs.rename(src, intermediate);
        if (firstRename) {
            // Process the file...
            // ok: java-hadoopcheckresultoffilerename
            boolean secondRename = fs.rename(intermediate, dst);
            if (!secondRename) {
                logger.warning("Failed to move processed file to final destination");
                // Handle failure
            }
        } else {
            logger.warning("Failed to move file to processing location");
            // Handle failure
        }
    }
}
// {/fact}