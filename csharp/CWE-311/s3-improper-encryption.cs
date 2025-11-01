using System;
using System.IO;
using System.Threading.Tasks;
using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S3EncryptionExamples
{
    public class S3EncryptionSamples
    {
// {fact rule=aws-kms-reencryption@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public static async Task bad_case_1()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var fileContent = File.ReadAllBytes("sensitive_data.txt");

            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(fileContent)
                // ruleid: s3-improper-encryption
                // No encryption specified
            };

            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_2()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Conditional encryption based on file size
            var fileContent = File.ReadAllBytes("sensitive_data.txt");
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(fileContent)
            };
            
            // ruleid: s3-improper-encryption
            if (fileContent.Length > 1024 * 1024) // Only encrypt files larger than 1MB
            {
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            }
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_3()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var transferUtility = new TransferUtility(s3Client);
            
            // ruleid: s3-improper-encryption
            var uploadRequest = new TransferUtilityUploadRequest
            {
                BucketName = "my-bucket",
                FilePath = "sensitive_data.txt",
                Key = "my-sensitive-file.txt"
                // Missing encryption configuration
            };
            
            await transferUtility.UploadAsync(uploadRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_4()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            bool isEncryptionEnabled = false; // Could be from a configuration
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt"))
            };
            
            // ruleid: s3-improper-encryption
            if (isEncryptionEnabled)
            {
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            }
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_5()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            string fileType = Path.GetExtension("sensitive_data.txt");
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt"))
            };
            
            // ruleid: s3-improper-encryption
            // Only encrypt certain file types
            if (fileType == ".pdf" || fileType == ".docx")
            {
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            }
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_6()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // ruleid: s3-improper-encryption
            var copyRequest = new CopyObjectRequest
            {
                SourceBucket = "source-bucket",
                SourceKey = "source-key",
                DestinationBucket = "destination-bucket",
                DestinationKey = "destination-key"
                // No encryption specified for the copied object
            };
            
            await s3Client.CopyObjectAsync(copyRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_7()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            string environment = Environment.GetEnvironmentVariable("ENVIRONMENT");
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt"))
            };
            
            // ruleid: s3-improper-encryption
            // Only encrypt in production
            if (environment == "production")
            {
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            }
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_8()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var transferUtility = new TransferUtility(s3Client);
            
            string bucketName = "my-bucket";
            string keyName = "my-sensitive-file.txt";
            
            // ruleid: s3-improper-encryption
            // Direct upload without encryption settings
            await transferUtility.UploadAsync("sensitive_data.txt", bucketName, keyName);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_9()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Initialize multipart upload without encryption
            // ruleid: s3-improper-encryption
            var initiateRequest = new InitiateMultipartUploadRequest
            {
                BucketName = "my-bucket",
                Key = "large-sensitive-file.txt"
                // No encryption specified
            };
            
            var initResponse = await s3Client.InitiateMultipartUploadAsync(initiateRequest);
            
            // Upload parts would go here
            
            // Complete multipart upload
            var completeRequest = new CompleteMultipartUploadRequest
            {
                BucketName = "my-bucket",
                Key = "large-sensitive-file.txt",
                UploadId = initResponse.UploadId,
                PartETags = new List<PartETag>()
            };
            
            await s3Client.CompleteMultipartUploadAsync(completeRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_10()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var transferUtility = new TransferUtility(s3Client);
            
            var directoryPath = "sensitive_data_directory";
            
            // ruleid: s3-improper-encryption
            // Directory upload without encryption settings
            await transferUtility.UploadDirectoryAsync(directoryPath, "my-bucket");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_11()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Create bucket without default encryption
            // ruleid: s3-improper-encryption
            var createBucketRequest = new PutBucketRequest
            {
                BucketName = "new-sensitive-data-bucket",
                UseClientRegion = true
                // No default encryption configuration
            };
            
            await s3Client.PutBucketAsync(createBucketRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_12()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            bool isPublic = true;
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt"))
            };
            
            // ruleid: s3-improper-encryption
            // Only encrypt private files
            if (!isPublic)
            {
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            }
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_13()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Create presigned URL without ensuring encryption on upload
            // ruleid: s3-improper-encryption
            var urlRequest = new GetPreSignedUrlRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                Verb = HttpVerb.PUT,
                Expires = DateTime.UtcNow.AddHours(1)
                // No encryption requirements for the upload
            };
            
            string url = s3Client.GetPreSignedURL(urlRequest);
            Console.WriteLine($"Upload URL: {url}");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_14()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // ruleid: s3-improper-encryption
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt"))
            };
            
            try
            {
                // Try to encrypt but fall back to unencrypted if it fails
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
                await s3Client.PutObjectAsync(putRequest);
            }
            catch (Exception)
            {
                // If encryption fails, try without encryption
                putRequest.ServerSideEncryptionMethod = null;
                await s3Client.PutObjectAsync(putRequest);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public static async Task bad_case_15()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var metadata = new MetadataCollection();
            metadata["Sensitive"] = "false";
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("data.txt")),
                Metadata = metadata
            };
            
            // ruleid: s3-improper-encryption
            // Only encrypt if metadata indicates it's sensitive
            if (metadata["Sensitive"] == "true")
            {
                putRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            }
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        // True Negatives (Secure Code)

        public static async Task good_case_1()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var fileContent = File.ReadAllBytes("sensitive_data.txt");

            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(fileContent),
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };

            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_2()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var transferUtility = new TransferUtility(s3Client);
            
            var uploadRequest = new TransferUtilityUploadRequest
            {
                BucketName = "my-bucket",
                FilePath = "sensitive_data.txt",
                Key = "my-sensitive-file.txt",
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await transferUtility.UploadAsync(uploadRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_3()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            var copyRequest = new CopyObjectRequest
            {
                SourceBucket = "source-bucket",
                SourceKey = "source-key",
                DestinationBucket = "destination-bucket",
                DestinationKey = "destination-key",
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await s3Client.CopyObjectAsync(copyRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_4()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Initialize multipart upload with encryption
            var initiateRequest = new InitiateMultipartUploadRequest
            {
                BucketName = "my-bucket",
                Key = "large-sensitive-file.txt",
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            var initResponse = await s3Client.InitiateMultipartUploadAsync(initiateRequest);
            
            // Upload parts would go here
            
            // Complete multipart upload
            var completeRequest = new CompleteMultipartUploadRequest
            {
                BucketName = "my-bucket",
                Key = "large-sensitive-file.txt",
                UploadId = initResponse.UploadId,
                PartETags = new List<PartETag>()
            };
            
            await s3Client.CompleteMultipartUploadAsync(completeRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_5()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Create bucket with default encryption
            var serverSideEncryptionConfiguration = new ServerSideEncryptionConfiguration
            {
                ServerSideEncryptionRules = new List<ServerSideEncryptionRule>
                {
                    new ServerSideEncryptionRule
                    {
                        ServerSideEncryptionByDefault = new ServerSideEncryptionByDefault
                        {
                            // ok: s3-improper-encryption
                            ServerSideEncryptionAlgorithm = ServerSideEncryptionMethod.AES256
                        }
                    }
                }
            };
            
            var putBucketEncryptionRequest = new PutBucketEncryptionRequest
            {
                BucketName = "new-sensitive-data-bucket",
                ServerSideEncryptionConfiguration = serverSideEncryptionConfiguration
            };
            
            await s3Client.PutBucketEncryptionAsync(putBucketEncryptionRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_6()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Using KMS encryption
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt")),
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AWSKMS,
                ServerSideEncryptionKeyManagementServiceKeyId = "arn:aws:kms:us-east-1:123456789012:key/abcd1234-ab12-cd34-ef56-abcdef123456"
            };
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_7()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var transferUtility = new TransferUtility(s3Client);
            
            // Using client-side encryption with KMS
            var encryptionMaterials = new EncryptionMaterials("arn:aws:kms:us-east-1:123456789012:key/abcd1234-ab12-cd34-ef56-abcdef123456");
            var configuration = new AmazonS3CryptoConfiguration
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };
            
            // ok: s3-improper-encryption
            var cryptoClient = new AmazonS3EncryptionClient(configuration, encryptionMaterials);
            var cryptoTransferUtility = new TransferUtility(cryptoClient);
            
            await cryptoTransferUtility.UploadAsync("sensitive_data.txt", "my-bucket", "my-sensitive-file.txt");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_8()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Create presigned URL with encryption requirements
            var urlRequest = new GetPreSignedUrlRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                Verb = HttpVerb.PUT,
                Expires = DateTime.UtcNow.AddHours(1)
            };
            
            // ok: s3-improper-encryption
            urlRequest.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            
            string url = s3Client.GetPreSignedURL(urlRequest);
            Console.WriteLine($"Upload URL: {url}");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_9()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Always encrypt regardless of file type
            string fileType = Path.GetExtension("sensitive_data.txt");
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt")),
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_10()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            bool isEncryptionEnabled = false; // Could be from a configuration
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt")),
                // ok: s3-improper-encryption
                // Always encrypt regardless of configuration
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_11()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            var transferUtility = new TransferUtility(s3Client);
            
            // Configure directory upload with encryption
            var directoryRequest = new TransferUtilityUploadDirectoryRequest
            {
                Directory = "sensitive_data_directory",
                BucketName = "my-bucket",
                SearchPattern = "*.*",
                SearchOption = SearchOption.AllDirectories,
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await transferUtility.UploadDirectoryAsync(directoryRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_12()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Using client-side encryption with a client-provided key
            byte[] encryptionKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(encryptionKey);
            }
            
            // ok: s3-improper-encryption
            var encryptionMaterials = new EncryptionMaterials(encryptionKey);
            var configuration = new AmazonS3CryptoConfiguration
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };
            
            var cryptoClient = new AmazonS3EncryptionClient(configuration, encryptionMaterials);
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt"))
            };
            
            await cryptoClient.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_13()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            string environment = Environment.GetEnvironmentVariable("ENVIRONMENT");
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt")),
                // ok: s3-improper-encryption
                // Always encrypt regardless of environment
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_14()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            bool isPublic = true;
            
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt")),
                // ok: s3-improper-encryption
                // Always encrypt regardless of public/private status
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            await s3Client.PutObjectAsync(putRequest);
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public static async Task good_case_15()
        {
            var s3Client = new AmazonS3Client(RegionEndpoint.USEast1);
            
            // Ensure encryption is always applied, even in error handling scenarios
            var putRequest = new PutObjectRequest
            {
                BucketName = "my-bucket",
                Key = "my-sensitive-file.txt",
                InputStream = new MemoryStream(File.ReadAllBytes("sensitive_data.txt")),
                // ok: s3-improper-encryption
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
            };
            
            try
            {
                await s3Client.PutObjectAsync(putRequest);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error uploading file: {ex.Message}");
                // Try with a different bucket but still maintain encryption
                putRequest.BucketName = "backup-bucket";
                await s3Client.PutObjectAsync(putRequest);
            }
        }
// {/fact}
    }
}