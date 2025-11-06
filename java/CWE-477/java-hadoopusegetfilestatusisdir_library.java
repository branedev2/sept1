import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.fs.viewfs.ViewFileSystem;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.adl.AdlFileSystem;
import org.apache.hadoop.fs.azure.NativeAzureFileSystem;
import org.apache.hadoop.fs.local.LocalFileSystem;
import org.apache.hadoop.fs.ftp.FTPFileSystem;
import org.apache.hadoop.fs.http.HttpFileSystem;
import org.apache.hadoop.fs.sftp.SFTPFileSystem;
import org.apache.hadoop.fs.webhdfs.WebHdfsFileSystem;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.fs.shell.PathData;
import org.apache.hadoop.fs.shell.Command;
import org.apache.hadoop.fs.shell.CommandFactory;
import org.apache.hadoop.fs.shell.FsCommand;
import org.apache.hadoop.fs.shell.Display;
import org.apache.hadoop.fs.shell.Count;
import org.apache.hadoop.fs.shell.Ls;
import org.apache.hadoop.fs.shell.Mkdir;
import org.apache.hadoop.fs.shell.Stat;
import org.apache.hadoop.fs.shell.Touch;
import org.apache.hadoop.fs.shell.Delete;
import org.apache.hadoop.fs.shell.CopyCommands;
import org.apache.hadoop.fs.shell.Find;
import org.apache.hadoop.fs.shell.Tail;
import org.apache.hadoop.fs.shell.Test;
import org.apache.hadoop.fs.shell.Truncate;
import org.apache.hadoop.fs.shell.SetReplication;
import org.apache.hadoop.fs.shell.SetSpaceQuota;
import org.apache.hadoop.fs.shell.SetXAttr;
import org.apache.hadoop.fs.shell.GetXAttr;
import org.apache.hadoop.fs.shell.ListXAttr;
import org.apache.hadoop.fs.shell.RemoveXAttr;
import org.apache.hadoop.fs.shell.DFSAdmin;
import org.apache.hadoop.fs.shell.FsShell;
import org.apache.hadoop.fs.shell.FsUsage;
import org.apache.hadoop.fs.shell.MoveCommands;
import org.apache.hadoop.fs.shell.SnapshotCommands;
import org.apache.hadoop.fs.shell.AclCommands;
import org.apache.hadoop.fs.shell.CacheCommands;
import org.apache.hadoop.fs.shell.StoragePolicyCommands;
import org.apache.hadoop.fs.shell.SnapshotDiffCommands;
import org.apache.hadoop.fs.shell.SnapshotShellCommands;
import org.apache.hadoop.fs.shell.PathExceptions;
import org.apache.hadoop.fs.shell.PathData;
import org.apache.hadoop.fs.shell.CommandFormat;
import org.apache.hadoop.fs.shell.CommandFormatException;
import org.apache.hadoop.fs.shell.CommandFormat.NotEnoughArgumentsException;
import org.apache.hadoop.fs.shell.CommandFormat.UnknownOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.IllegalNumberOfArgumentsException;
import org.apache.hadoop.fs.shell.CommandFormat.TooManyArgumentsException;
import org.apache.hadoop.fs.shell.CommandFormat.UnknownOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.IllegalArgumentException;
import org.apache.hadoop.fs.shell.CommandFormat.DuplicatedOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.MissingOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.MissingArgumentException;
import org.apache.hadoop.fs.shell.CommandFormat.IllegalNumberOfArgumentsException;
import org.apache.hadoop.fs.shell.CommandFormat.TooManyArgumentsException;
import org.apache.hadoop.fs.shell.CommandFormat.UnknownOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.IllegalArgumentException;
import org.apache.hadoop.fs.shell.CommandFormat.DuplicatedOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.MissingOptionException;
import org.apache.hadoop.fs.shell.CommandFormat.MissingArgumentException;
import java.io.IOException;

// Security Issue: Using deprecated FileSystem.isDirectory() method instead of the recommended FileStatus.isDirectory()

// True Positive Examples (Vulnerable/Insecure Code)
public class HadoopFileSystemDeprecationExamples {

// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        // Using deprecated isDirectory() with standard HDFS FileSystem
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/data/logs");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = fs.isDirectory(path);
        
        if (isDir) {
            System.out.println("Path is a directory");
        }
    }

    public void bad_case_2() throws IOException {
        // Using deprecated isDirectory() with DistributedFileSystem
        Configuration conf = new Configuration();
        DistributedFileSystem dfs = (DistributedFileSystem) FileSystem.get(conf);
        Path path = new Path("/user/hadoop/input");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (dfs.isDirectory(path)) {
            System.out.println("Processing directory: " + path);
        }
    }

    public void bad_case_3() throws IOException {
        // Using deprecated isDirectory() in MapReduce job setup
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path inputPath = new Path("/user/hadoop/mapreduce/input");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (!fs.isDirectory(inputPath)) {
            throw new IOException("Input path is not a directory");
        }
        
        Job job = Job.getInstance(conf, "WordCount");
        FileInputFormat.addInputPath(job, inputPath);
    }

    public void bad_case_4() throws IOException {
        // Using deprecated isDirectory() with ViewFileSystem
        Configuration conf = new Configuration();
        ViewFileSystem viewFs = (ViewFileSystem) FileSystem.get(conf);
        Path path = new Path("/user/data/views");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = viewFs.isDirectory(path);
        
        if (isDir) {
            System.out.println("Path is a directory in ViewFileSystem");
        }
    }

    public void bad_case_5() throws IOException {
        // Using deprecated isDirectory() with S3AFileSystem
        Configuration conf = new Configuration();
        S3AFileSystem s3aFs = (S3AFileSystem) FileSystem.get(conf);
        Path path = new Path("s3a://mybucket/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (s3aFs.isDirectory(path)) {
            System.out.println("S3 path is a directory");
        }
    }

    public void bad_case_6() throws IOException {
        // Using deprecated isDirectory() with AdlFileSystem
        Configuration conf = new Configuration();
        AdlFileSystem adlFs = (AdlFileSystem) FileSystem.get(conf);
        Path path = new Path("adl://mydatalake/logs");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = adlFs.isDirectory(path);
        
        if (isDir) {
            System.out.println("ADL path is a directory");
        }
    }

    public void bad_case_7() throws IOException {
        // Using deprecated isDirectory() with NativeAzureFileSystem
        Configuration conf = new Configuration();
        NativeAzureFileSystem azureFs = (NativeAzureFileSystem) FileSystem.get(conf);
        Path path = new Path("wasb://container@account.blob.core.windows.net/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (azureFs.isDirectory(path)) {
            System.out.println("Azure path is a directory");
        }
    }

    public void bad_case_8() throws IOException {
        // Using deprecated isDirectory() with LocalFileSystem
        Configuration conf = new Configuration();
        LocalFileSystem localFs = (LocalFileSystem) FileSystem.getLocal(conf);
        Path path = new Path("/tmp/hadoop/local");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = localFs.isDirectory(path);
        
        if (isDir) {
            System.out.println("Local path is a directory");
        }
    }

    public void bad_case_9() throws IOException {
        // Using deprecated isDirectory() with FTPFileSystem
        Configuration conf = new Configuration();
        FTPFileSystem ftpFs = (FTPFileSystem) FileSystem.get(conf);
        Path path = new Path("ftp://user:pass@ftpserver/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (ftpFs.isDirectory(path)) {
            System.out.println("FTP path is a directory");
        }
    }

    public void bad_case_10() throws IOException {
        // Using deprecated isDirectory() with HttpFileSystem
        Configuration conf = new Configuration();
        HttpFileSystem httpFs = (HttpFileSystem) FileSystem.get(conf);
        Path path = new Path("http://example.com/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = httpFs.isDirectory(path);
        
        if (isDir) {
            System.out.println("HTTP path is a directory");
        }
    }

    public void bad_case_11() throws IOException {
        // Using deprecated isDirectory() with SFTPFileSystem
        Configuration conf = new Configuration();
        SFTPFileSystem sftpFs = (SFTPFileSystem) FileSystem.get(conf);
        Path path = new Path("sftp://user:pass@sftpserver/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (sftpFs.isDirectory(path)) {
            System.out.println("SFTP path is a directory");
        }
    }

    public void bad_case_12() throws IOException {
        // Using deprecated isDirectory() with WebHdfsFileSystem
        Configuration conf = new Configuration();
        WebHdfsFileSystem webHdfsFs = (WebHdfsFileSystem) FileSystem.get(conf);
        Path path = new Path("webhdfs://namenode:50070/user/data");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        boolean isDir = webHdfsFs.isDirectory(path);
        
        if (isDir) {
            System.out.println("WebHDFS path is a directory");
        }
    }

    public void bad_case_13() throws IOException {
        // Using deprecated isDirectory() in a custom shell command implementation
        class MyCommand extends FsCommand {
            public void processPath(PathData item) throws IOException {
                FileSystem fs = item.fs;
                Path path = item.path;
                
                // ruleid: java-hadoopusegetfilestatusisdir
                if (fs.isDirectory(path)) {
                    System.out.println(path + " is a directory");
                }
            }
        }
    }

    public void bad_case_14() throws IOException {
        // Using deprecated isDirectory() in a recursive directory traversal
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path rootPath = new Path("/user/hadoop/data");
        
        traverseDirectory(fs, rootPath);
    }
    
    private void traverseDirectory(FileSystem fs, Path path) throws IOException {
        // ruleid: java-hadoopusegetfilestatusisdir
        if (fs.isDirectory(path)) {
            for (FileStatus status : fs.listStatus(path)) {
                traverseDirectory(fs, status.getPath());
            }
        } else {
            System.out.println("Found file: " + path);
        }
    }

    public void bad_case_15() throws IOException {
        // Using deprecated isDirectory() in a file operation utility
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path sourcePath = new Path("/user/hadoop/source");
        Path targetPath = new Path("/user/hadoop/target");
        
        // ruleid: java-hadoopusegetfilestatusisdir
        if (fs.isDirectory(sourcePath)) {
            // Copy directory contents
            if (!fs.exists(targetPath)) {
                fs.mkdirs(targetPath);
            }
            
            FileStatus[] files = fs.listStatus(sourcePath);
            for (FileStatus file : files) {
                Path src = file.getPath();
                Path dst = new Path(targetPath, src.getName());
                fs.copy(src, dst, false, true);
            }
        } else {
            // Copy single file
            fs.copy(sourcePath, targetPath, false, true);
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() throws IOException {
        // Using recommended FileStatus.isDirectory() with standard HDFS FileSystem
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path path = new Path("/user/data/logs");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = fs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        if (isDir) {
            System.out.println("Path is a directory");
        }
    }

    public void good_case_2() throws IOException {
        // Using recommended FileStatus.isDirectory() with DistributedFileSystem
        Configuration conf = new Configuration();
        DistributedFileSystem dfs = (DistributedFileSystem) FileSystem.get(conf);
        Path path = new Path("/user/hadoop/input");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = dfs.getFileStatus(path);
        if (status.isDirectory()) {
            System.out.println("Processing directory: " + path);
        }
    }

    public void good_case_3() throws IOException {
        // Using recommended FileStatus.isDirectory() in MapReduce job setup
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path inputPath = new Path("/user/hadoop/mapreduce/input");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = fs.getFileStatus(inputPath);
        if (!status.isDirectory()) {
            throw new IOException("Input path is not a directory");
        }
        
        Job job = Job.getInstance(conf, "WordCount");
        FileInputFormat.addInputPath(job, inputPath);
    }

    public void good_case_4() throws IOException {
        // Using recommended FileStatus.isDirectory() with ViewFileSystem
        Configuration conf = new Configuration();
        ViewFileSystem viewFs = (ViewFileSystem) FileSystem.get(conf);
        Path path = new Path("/user/data/views");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = viewFs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        if (isDir) {
            System.out.println("Path is a directory in ViewFileSystem");
        }
    }

    public void good_case_5() throws IOException {
        // Using recommended FileStatus.isDirectory() with S3AFileSystem
        Configuration conf = new Configuration();
        S3AFileSystem s3aFs = (S3AFileSystem) FileSystem.get(conf);
        Path path = new Path("s3a://mybucket/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = s3aFs.getFileStatus(path);
        if (status.isDirectory()) {
            System.out.println("S3 path is a directory");
        }
    }

    public void good_case_6() throws IOException {
        // Using recommended FileStatus.isDirectory() with AdlFileSystem
        Configuration conf = new Configuration();
        AdlFileSystem adlFs = (AdlFileSystem) FileSystem.get(conf);
        Path path = new Path("adl://mydatalake/logs");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = adlFs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        if (isDir) {
            System.out.println("ADL path is a directory");
        }
    }

    public void good_case_7() throws IOException {
        // Using recommended FileStatus.isDirectory() with NativeAzureFileSystem
        Configuration conf = new Configuration();
        NativeAzureFileSystem azureFs = (NativeAzureFileSystem) FileSystem.get(conf);
        Path path = new Path("wasb://container@account.blob.core.windows.net/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = azureFs.getFileStatus(path);
        if (status.isDirectory()) {
            System.out.println("Azure path is a directory");
        }
    }

    public void good_case_8() throws IOException {
        // Using recommended FileStatus.isDirectory() with LocalFileSystem
        Configuration conf = new Configuration();
        LocalFileSystem localFs = (LocalFileSystem) FileSystem.getLocal(conf);
        Path path = new Path("/tmp/hadoop/local");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = localFs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        if (isDir) {
            System.out.println("Local path is a directory");
        }
    }

    public void good_case_9() throws IOException {
        // Using recommended FileStatus.isDirectory() with FTPFileSystem
        Configuration conf = new Configuration();
        FTPFileSystem ftpFs = (FTPFileSystem) FileSystem.get(conf);
        Path path = new Path("ftp://user:pass@ftpserver/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = ftpFs.getFileStatus(path);
        if (status.isDirectory()) {
            System.out.println("FTP path is a directory");
        }
    }

    public void good_case_10() throws IOException {
        // Using recommended FileStatus.isDirectory() with HttpFileSystem
        Configuration conf = new Configuration();
        HttpFileSystem httpFs = (HttpFileSystem) FileSystem.get(conf);
        Path path = new Path("http://example.com/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = httpFs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        if (isDir) {
            System.out.println("HTTP path is a directory");
        }
    }

    public void good_case_11() throws IOException {
        // Using recommended FileStatus.isDirectory() with SFTPFileSystem
        Configuration conf = new Configuration();
        SFTPFileSystem sftpFs = (SFTPFileSystem) FileSystem.get(conf);
        Path path = new Path("sftp://user:pass@sftpserver/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = sftpFs.getFileStatus(path);
        if (status.isDirectory()) {
            System.out.println("SFTP path is a directory");
        }
    }

    public void good_case_12() throws IOException {
        // Using recommended FileStatus.isDirectory() with WebHdfsFileSystem
        Configuration conf = new Configuration();
        WebHdfsFileSystem webHdfsFs = (WebHdfsFileSystem) FileSystem.get(conf);
        Path path = new Path("webhdfs://namenode:50070/user/data");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = webHdfsFs.getFileStatus(path);
        boolean isDir = status.isDirectory();
        
        if (isDir) {
            System.out.println("WebHDFS path is a directory");
        }
    }

    public void good_case_13() throws IOException {
        // Using recommended FileStatus.isDirectory() in a custom shell command implementation
        class MyCommand extends FsCommand {
            public void processPath(PathData item) throws IOException {
                FileSystem fs = item.fs;
                Path path = item.path;
                
                // ok: java-hadoopusegetfilestatusisdir
                FileStatus status = fs.getFileStatus(path);
                if (status.isDirectory()) {
                    System.out.println(path + " is a directory");
                }
            }
        }
    }

    public void good_case_14() throws IOException {
        // Using recommended FileStatus.isDirectory() in a recursive directory traversal
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path rootPath = new Path("/user/hadoop/data");
        
        traverseDirectorySafely(fs, rootPath);
    }
    
    private void traverseDirectorySafely(FileSystem fs, Path path) throws IOException {
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus status = fs.getFileStatus(path);
        if (status.isDirectory()) {
            for (FileStatus childStatus : fs.listStatus(path)) {
                traverseDirectorySafely(fs, childStatus.getPath());
            }
        } else {
            System.out.println("Found file: " + path);
        }
    }

    public void good_case_15() throws IOException {
        // Using recommended FileStatus.isDirectory() in a file operation utility
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        Path sourcePath = new Path("/user/hadoop/source");
        Path targetPath = new Path("/user/hadoop/target");
        
        // ok: java-hadoopusegetfilestatusisdir
        FileStatus sourceStatus = fs.getFileStatus(sourcePath);
        if (sourceStatus.isDirectory()) {
            // Copy directory contents
            if (!fs.exists(targetPath)) {
                fs.mkdirs(targetPath);
            }
            
            FileStatus[] files = fs.listStatus(sourcePath);
            for (FileStatus file : files) {
                Path src = file.getPath();
                Path dst = new Path(targetPath, src.getName());
                fs.copy(src, dst, false, true);
            }
        } else {
            // Copy single file
            fs.copy(sourcePath, targetPath, false, true);
        }
    }
}
// {/fact}