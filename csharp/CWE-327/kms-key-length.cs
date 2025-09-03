using System;
using System.Threading;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace KmsKeyLengthTests
{
    public class KmsKeyLengthExamples
    {
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public async Task bad_case_1()
        {
            // Setting both KeySpec and NumberOfBytes
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ruleid: kms-key-length
                KeySpec = DataKeySpec.AES_256,
                NumberOfBytes = 32
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_2()
        {
            // Using a key that is less than 256 bits (128 bits = 16 bytes)
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ruleid: kms-key-length
                NumberOfBytes = 16
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_3()
        {
            // Using a key that is less than 256 bits (192 bits = 24 bytes)
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            // ruleid: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                NumberOfBytes = 24
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_4()
        {
            // Setting both KeySpec and NumberOfBytes in a variable
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var request = new GenerateDataKeyRequest();
            request.KeyId = "alias/my-key";
            request.KeySpec = DataKeySpec.AES_128;
            // ruleid: kms-key-length
            request.NumberOfBytes = 16;
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_5()
        {
            // Using a weak key (64 bits = 8 bytes)
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            // ruleid: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                NumberOfBytes = 8
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_6()
        {
            // Using a weak key with conditional logic
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key"
            };
            
            bool useSmallKey = true;
            if (useSmallKey)
            {
                // ruleid: kms-key-length
                request.NumberOfBytes = 20; // 160 bits
            }
            else
            {
                request.KeySpec = DataKeySpec.AES_256;
            }
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_7()
        {
            // Setting both properties with one in a conditional
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                KeySpec = DataKeySpec.AES_256
            };
            
            bool addBytes = true;
            if (addBytes)
            {
                // ruleid: kms-key-length
                request.NumberOfBytes = 32;
            }
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_8()
        {
            // Using a calculated weak key size
            var kmsClient = new AmazonKeyManagementServiceClient();
            int keySize = 8 * 10; // 80 bits
            
            // ruleid: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                NumberOfBytes = keySize / 8
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_9()
        {
            // Using a weak key with AES_128
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            // ruleid: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                KeySpec = DataKeySpec.AES_128
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_10()
        {
            // Using both properties with method chaining
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var request = new GenerateDataKeyRequest()
                .WithKeyId("alias/my-key")
                .WithKeySpec(DataKeySpec.AES_256);
                
            // ruleid: kms-key-length
            request.NumberOfBytes = 32;
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_11()
        {
            // Using a weak key with a loop
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            for (int i = 0; i < 3; i++)
            {
                // ruleid: kms-key-length
                var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
                {
                    KeyId = $"alias/my-key-{i}",
                    NumberOfBytes = 12 // 96 bits
                });
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_12()
        {
            // Using a weak key with a switch statement
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key"
            };
            
            int securityLevel = 1;
            switch (securityLevel)
            {
                case 1:
                    // ruleid: kms-key-length
                    request.NumberOfBytes = 16; // 128 bits
                    break;
                case 2:
                    request.KeySpec = DataKeySpec.AES_256;
                    break;
            }
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_13()
        {
            // Using both properties with one from a variable
            var kmsClient = new AmazonKeyManagementServiceClient();
            var keySpec = DataKeySpec.AES_256;
            
            // ruleid: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                KeySpec = keySpec,
                NumberOfBytes = 32
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_14()
        {
            // Using a weak key with a ternary operator
            var kmsClient = new AmazonKeyManagementServiceClient();
            bool useStrongKey = false;
            
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ruleid: kms-key-length
                NumberOfBytes = useStrongKey ? 32 : 16
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public async Task bad_case_15()
        {
            // Using a weak key with an array of requests
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var requests = new GenerateDataKeyRequest[]
            {
                new GenerateDataKeyRequest { KeyId = "alias/my-key-1", KeySpec = DataKeySpec.AES_256 },
                // ruleid: kms-key-length
                new GenerateDataKeyRequest { KeyId = "alias/my-key-2", NumberOfBytes = 20 }
            };
            
            foreach (var request in requests)
            {
                var response = await kmsClient.GenerateDataKeyAsync(request);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        // True Negatives (Secure Code)

        public async Task good_case_1()
        {
            // Using only KeySpec with AES_256
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ok: kms-key-length
                KeySpec = DataKeySpec.AES_256
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_2()
        {
            // Using NumberOfBytes with 32 bytes (256 bits)
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ok: kms-key-length
                NumberOfBytes = 32
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_3()
        {
            // Using NumberOfBytes with 64 bytes (512 bits)
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            // ok: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                NumberOfBytes = 64
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_4()
        {
            // Using KeySpec with RSA_2048
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var request = new GenerateDataKeyRequest();
            request.KeyId = "alias/my-key";
            // ok: kms-key-length
            request.KeySpec = DataKeySpec.RSA_2048;
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_5()
        {
            // Using KeySpec with RSA_4096
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            // ok: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                KeySpec = DataKeySpec.RSA_4096
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_6()
        {
            // Using NumberOfBytes with conditional logic for strong keys
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key"
            };
            
            bool useStrongerKey = true;
            if (useStrongerKey)
            {
                // ok: kms-key-length
                request.NumberOfBytes = 64; // 512 bits
            }
            else
            {
                request.NumberOfBytes = 32; // 256 bits
            }
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_7()
        {
            // Using KeySpec with method chaining
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var request = new GenerateDataKeyRequest()
                .WithKeyId("alias/my-key");
                
            // ok: kms-key-length
            request.KeySpec = DataKeySpec.AES_256;
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_8()
        {
            // Using a calculated strong key size
            var kmsClient = new AmazonKeyManagementServiceClient();
            int keySize = 256; // bits
            
            // ok: kms-key-length
            var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                NumberOfBytes = keySize / 8
            });
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_9()
        {
            // Using a strong key with a loop
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            for (int i = 0; i < 3; i++)
            {
                // ok: kms-key-length
                var response = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
                {
                    KeyId = $"alias/my-key-{i}",
                    KeySpec = DataKeySpec.AES_256
                });
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_10()
        {
            // Using a strong key with a switch statement
            var kmsClient = new AmazonKeyManagementServiceClient();
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key"
            };
            
            int securityLevel = 2;
            switch (securityLevel)
            {
                case 1:
                    // ok: kms-key-length
                    request.NumberOfBytes = 32; // 256 bits
                    break;
                case 2:
                    request.KeySpec = DataKeySpec.AES_256;
                    break;
            }
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_11()
        {
            // Using a strong key with a ternary operator
            var kmsClient = new AmazonKeyManagementServiceClient();
            bool useRsa = true;
            
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ok: kms-key-length
                KeySpec = useRsa ? DataKeySpec.RSA_4096 : DataKeySpec.AES_256
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_12()
        {
            // Using a strong key with an array of requests
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var requests = new GenerateDataKeyRequest[]
            {
                new GenerateDataKeyRequest { KeyId = "alias/my-key-1", KeySpec = DataKeySpec.AES_256 },
                // ok: kms-key-length
                new GenerateDataKeyRequest { KeyId = "alias/my-key-2", NumberOfBytes = 32 }
            };
            
            foreach (var request in requests)
            {
                var response = await kmsClient.GenerateDataKeyAsync(request);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_13()
        {
            // Using a strong key with a dictionary
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var keyConfigs = new Dictionary<string, object>
            {
                ["KeyId"] = "alias/my-key",
                ["KeySpec"] = DataKeySpec.AES_256
            };
            
            var request = new GenerateDataKeyRequest
            {
                KeyId = (string)keyConfigs["KeyId"],
                // ok: kms-key-length
                KeySpec = (DataKeySpec)keyConfigs["KeySpec"]
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_14()
        {
            // Using a strong key with environment configuration
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            // Simulate getting config from environment
            int minKeySize = 32; // Minimum bytes required by policy
            
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key",
                // ok: kms-key-length
                NumberOfBytes = Math.Max(32, minKeySize) // Ensures at least 256 bits
            };
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public async Task good_case_15()
        {
            // Using a strong key with a helper method
            var kmsClient = new AmazonKeyManagementServiceClient();
            
            var request = new GenerateDataKeyRequest
            {
                KeyId = "alias/my-key"
            };
            
            // ok: kms-key-length
            ApplySecureKeySpec(request);
            
            var response = await kmsClient.GenerateDataKeyAsync(request);
        }
// {/fact}
        
        private void ApplySecureKeySpec(GenerateDataKeyRequest request)
        {
            request.KeySpec = DataKeySpec.AES_256;
        }
    }
}