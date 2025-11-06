import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.client.HdfsAdmin;
import org.apache.hadoop.hdfs.protocol.HdfsConstants;
import org.apache.hadoop.hdfs.server.namenode.NameNode;
import org.apache.hadoop.hdfs.tools.DFSAdmin;
import org.apache.hadoop.hdfs.web.WebHdfsFileSystem;
import org.apache.hadoop.fs.viewfs.ViewFileSystem;
import org.apache.hadoop.fs.adl.AdlFileSystem;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.azure.NativeAzureFileSystem;
import org.apache.hadoop.fs.ftp.FTPFileSystem;
import org.apache.hadoop.fs.local.LocalFileSystem;
import org.apache.hadoop.fs.sftp.SFTPFileSystem;
import org.apache.hadoop.fs.shell.PathData;
import org.apache.hadoop.fs.shell.CommandWithDestination;
import org.apache.hadoop.fs.shell.Move;
import org.apache.hadoop.fs.FileContext;
import org.apache.hadoop.fs.Options;
import org.apache.hadoop.fs.permission.FsPermission;
import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpGet;
import com.sun.net.httpserver.HttpExchange;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.net.URI;
import okhttp3.Request;
import okhttp3.Response;

// Security Issue: Not checking the result of HDFS rename() operations can lead to silent failures and data loss

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        hdfs.rename(src, dst);
        
        // No check if rename was successful
        System.out.println("File moved");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        DistributedFileSystem dfs = (DistributedFileSystem) FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        dfs.rename(src, dst);
        
        // Proceeding without checking result
        System.out.println("Rename operation executed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpExchange exchange) {
    try {
        String query = exchange.getRequestURI().getQuery();
        String[] params = query.split("&");
        String sourcePath = "";
        String destPath = "";
        
        for (String param : params) {
            String[] keyValue = param.split("=");
            if (keyValue[0].equals("source")) {
                sourcePath = keyValue[1];
            } else if (keyValue[0].equals("destination")) {
                destPath = keyValue[1];
            }
        }
        
        Configuration conf = new Configuration();
        WebHdfsFileSystem webHdfs = (WebHdfsFileSystem) FileSystem.get(URI.create("webhdfs://localhost:50070"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        webHdfs.rename(src, dst);
        
        // No verification of rename success
        exchange.sendResponseHeaders(200, 0);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_4(@RequestParam String source, @RequestParam String destination) {
    try {
        Configuration conf = new Configuration();
        ViewFileSystem viewFs = (ViewFileSystem) FileSystem.get(conf);
        Path src = new Path(source);
        Path dst = new Path(destination);
        
        // ruleid: java-hadoopcheckresultoffilerename
        viewFs.rename(src, dst);
        
        // Assuming success without verification
        System.out.println("File renamed successfully");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        AdlFileSystem adlFs = (AdlFileSystem) FileSystem.get(URI.create("adl://account.azuredatalakestore.net"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        adlFs.rename(src, dst);
        
        // Proceeding without checking result
        System.out.println("Rename operation completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        S3AFileSystem s3aFs = (S3AFileSystem) FileSystem.get(URI.create("s3a://bucket/"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        s3aFs.rename(src, dst);
        
        // Missing result check
        System.out.println("S3 file rename operation issued");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        NativeAzureFileSystem azureFs = (NativeAzureFileSystem) FileSystem.get(URI.create("wasb://container@account.blob.core.windows.net"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        azureFs.rename(src, dst);
        
        // No verification of success
        System.out.println("Azure blob rename operation completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FTPFileSystem ftpFs = (FTPFileSystem) FileSystem.get(URI.create("ftp://user:pass@host:port/"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        ftpFs.rename(src, dst);
        
        // Missing result check
        System.out.println("FTP file rename completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        LocalFileSystem localFs = (LocalFileSystem) FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        localFs.rename(src, dst);
        
        // No verification
        System.out.println("Local file rename operation executed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        SFTPFileSystem sftpFs = (SFTPFileSystem) FileSystem.get(URI.create("sftp://user:pass@host:port/"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        sftpFs.rename(src, dst);
        
        // Missing result verification
        System.out.println("SFTP file rename operation issued");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        
        // Using PathData for file operations
        PathData src = new PathData(sourcePath, conf);
        PathData dst = new PathData(destPath, conf);
        
        // ruleid: java-hadoopcheckresultoffilerename
        src.fs.rename(src.path, dst.path);
        
        // No check if rename was successful
        System.out.println("PathData rename completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FileContext fileContext = FileContext.getFileContext(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        fileContext.rename(src, dst);
        
        // Missing result check
        System.out.println("FileContext rename operation completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        // Using Move command from shell utilities
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Move moveCommand = new Move();
        moveCommand.setConf(conf);
        
        String[] args = {sourcePath, destPath};
        
        // ruleid: java-hadoopcheckresultoffilerename
        moveCommand.run(args);
        
        // No verification of success
        System.out.println("Move command executed");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        DFSAdmin dfsAdmin = new DFSAdmin(conf);
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(src, dst);
        
        // No check of rename result
        System.out.println("Admin rename operation completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        HdfsAdmin hdfsAdmin = new HdfsAdmin(URI.create("hdfs://localhost:9000"), conf);
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ruleid: java-hadoopcheckresultoffilerename
        fs.rename(src, dst);
        
        // Missing result verification
        System.out.println("HDFS admin rename completed");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean renameSuccess = hdfs.rename(src, dst);
        
        if (renameSuccess) {
            System.out.println("File moved successfully");
        } else {
            System.out.println("Failed to move file");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        DistributedFileSystem dfs = (DistributedFileSystem) FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = dfs.rename(src, dst);
        
        if (!success) {
            throw new IOException("Failed to rename file from " + src + " to " + dst);
        }
        System.out.println("Rename operation successful");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpExchange exchange) {
    try {
        String query = exchange.getRequestURI().getQuery();
        String[] params = query.split("&");
        String sourcePath = "";
        String destPath = "";
        
        for (String param : params) {
            String[] keyValue = param.split("=");
            if (keyValue[0].equals("source")) {
                sourcePath = keyValue[1];
            } else if (keyValue[0].equals("destination")) {
                destPath = keyValue[1];
            }
        }
        
        Configuration conf = new Configuration();
        WebHdfsFileSystem webHdfs = (WebHdfsFileSystem) FileSystem.get(URI.create("webhdfs://localhost:50070"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean renameResult = webHdfs.rename(src, dst);
        
        if (renameResult) {
            exchange.sendResponseHeaders(200, 0);
        } else {
            exchange.sendResponseHeaders(500, 0);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4(@RequestParam String source, @RequestParam String destination) {
    try {
        Configuration conf = new Configuration();
        ViewFileSystem viewFs = (ViewFileSystem) FileSystem.get(conf);
        Path src = new Path(source);
        Path dst = new Path(destination);
        
        // ok: java-hadoopcheckresultoffilerename
        if (viewFs.rename(src, dst)) {
            System.out.println("File renamed successfully");
        } else {
            System.out.println("File rename failed");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        AdlFileSystem adlFs = (AdlFileSystem) FileSystem.get(URI.create("adl://account.azuredatalakestore.net"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean renameResult = adlFs.rename(src, dst);
        
        if (renameResult) {
            System.out.println("Rename operation successful");
        } else {
            System.out.println("Rename operation failed");
            // Take appropriate action for failure
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        S3AFileSystem s3aFs = (S3AFileSystem) FileSystem.get(URI.create("s3a://bucket/"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = s3aFs.rename(src, dst);
        
        if (success) {
            System.out.println("S3 file rename successful");
        } else {
            System.out.println("S3 file rename failed");
            // Handle the failure case
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        NativeAzureFileSystem azureFs = (NativeAzureFileSystem) FileSystem.get(URI.create("wasb://container@account.blob.core.windows.net"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        if (!azureFs.rename(src, dst)) {
            throw new RuntimeException("Failed to rename Azure blob from " + src + " to " + dst);
        }
        System.out.println("Azure blob rename operation successful");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FTPFileSystem ftpFs = (FTPFileSystem) FileSystem.get(URI.create("ftp://user:pass@host:port/"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean result = ftpFs.rename(src, dst);
        
        if (result) {
            System.out.println("FTP file rename successful");
        } else {
            System.out.println("FTP file rename failed");
            // Log the failure and take appropriate action
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        LocalFileSystem localFs = (LocalFileSystem) FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = localFs.rename(src, dst);
        
        if (success) {
            System.out.println("Local file rename successful");
        } else {
            System.out.println("Local file rename failed");
            // Handle the failure appropriately
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        SFTPFileSystem sftpFs = (SFTPFileSystem) FileSystem.get(URI.create("sftp://user:pass@host:port/"), conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean renameSuccess = sftpFs.rename(src, dst);
        
        if (!renameSuccess) {
            System.err.println("SFTP file rename failed");
            // Take appropriate action for failure
        } else {
            System.out.println("SFTP file rename successful");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FileSystem hdfs = FileSystem.get(conf);
        
        // Using PathData for file operations
        PathData src = new PathData(sourcePath, conf);
        PathData dst = new PathData(destPath, conf);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = src.fs.rename(src.path, dst.path);
        
        if (success) {
            System.out.println("PathData rename successful");
        } else {
            System.out.println("PathData rename failed");
            // Handle failure case
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        FileContext fileContext = FileContext.getFileContext(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        try {
            // ok: java-hadoopcheckresultoffilerename
            fileContext.rename(src, dst);
            System.out.println("FileContext rename successful");
        } catch (IOException e) {
            System.out.println("FileContext rename failed: " + e.getMessage());
            // Handle the exception appropriately
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        // Using Move command from shell utilities with proper error handling
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Move moveCommand = new Move();
        moveCommand.setConf(conf);
        
        String[] args = {sourcePath, destPath};
        
        try {
            // ok: java-hadoopcheckresultoffilerename
            int exitCode = moveCommand.run(args);
            if (exitCode == 0) {
                System.out.println("Move command executed successfully");
            } else {
                System.out.println("Move command failed with exit code: " + exitCode);
                // Handle failure appropriately
            }
        } catch (Exception e) {
            System.out.println("Move command failed: " + e.getMessage());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        DFSAdmin dfsAdmin = new DFSAdmin(conf);
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean success = fs.rename(src, dst);
        
        if (success) {
            System.out.println("Admin rename operation successful");
        } else {
            System.out.println("Admin rename operation failed");
            // Take appropriate action for failure
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    Logger logger = Logger.getLogger("HdfsRenameLogger");
    try {
        String sourcePath = request.getParameter("source");
        String destPath = request.getParameter("destination");
        
        Configuration conf = new Configuration();
        HdfsAdmin hdfsAdmin = new HdfsAdmin(URI.create("hdfs://localhost:9000"), conf);
        FileSystem fs = FileSystem.get(conf);
        Path src = new Path(sourcePath);
        Path dst = new Path(destPath);
        
        // ok: java-hadoopcheckresultoffilerename
        boolean renameResult = fs.rename(src, dst);
        
        if (renameResult) {
            logger.info("HDFS admin rename successful: " + src + " to " + dst);
        } else {
            logger.warning("HDFS admin rename failed: " + src + " to " + dst);
            // Handle the failure case appropriately
        }
    } catch (IOException e) {
        logger.severe("Error during HDFS rename: " + e.getMessage());
        e.printStackTrace();
    }
}