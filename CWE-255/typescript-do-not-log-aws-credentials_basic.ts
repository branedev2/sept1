import * as AWS from 'aws-sdk';
import * as winston from 'winston';
import * as console from 'console';
import * as fs from 'fs';
import * as dotenv from 'dotenv';
import * as crypto from 'crypto';

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_1() {
    // Hardcoded AWS credentials directly logged to console
    const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
    const secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    // ruleid: typescript-do-not-log-aws-credentials
    console.log(`AWS Access Key: ${accessKeyId}, Secret: ${secretAccessKey}`);
    
    const s3 = new AWS.S3({
        accessKeyId,
        secretAccessKey,
        region: 'us-west-2'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_2() {
    // Logging AWS credentials in an error message
    try {
        const credentials = {
            accessKeyId: 'AKIAI44QH8DHBEXAMPLE',
            secretAccessKey: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY'
        };
        
        const ec2 = new AWS.EC2(credentials);
        // Some operation that might fail
        throw new Error('Connection failed');
    } catch (error) {
        const credentials = {
            accessKeyId: 'AKIAI44QH8DHBEXAMPLE',
            secretAccessKey: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY'
        };
        
        // ruleid: typescript-do-not-log-aws-credentials
        console.error('Failed with credentials:', credentials, error);
    }
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_3() {
    // Logging AWS credentials in a winston logger
    const logger = winston.createLogger({
        level: 'info',
        format: winston.format.json(),
        transports: [
            new winston.transports.Console(),
            new winston.transports.File({ filename: 'app.log' })
        ]
    });
    
    const awsConfig = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1'
    };
    
    // ruleid: typescript-do-not-log-aws-credentials
    logger.info('AWS Configuration:', awsConfig);
    
    const dynamodb = new AWS.DynamoDB(awsConfig);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_4() {
    // Logging AWS credentials to a file
    const credentials = {
        accessKey: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'eu-west-1'
    };
    
    // ruleid: typescript-do-not-log-aws-credentials
    fs.writeFileSync('debug_log.txt', JSON.stringify(credentials, null, 2));
    
    const lambda = new AWS.Lambda({
        accessKeyId: credentials.accessKey,
        secretAccessKey: credentials.secretKey,
        region: credentials.region
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_5() {
    // Logging AWS credentials in a debugging object
    const debugInfo = {
        timestamp: new Date().toISOString(),
        environment: 'production',
        awsCredentials: {
            accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
            secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
    };
    
    // ruleid: typescript-do-not-log-aws-credentials
    console.debug('Debug information:', debugInfo);
    
    const sns = new AWS.SNS({
        accessKeyId: debugInfo.awsCredentials.accessKeyId,
        secretAccessKey: debugInfo.awsCredentials.secretAccessKey,
        region: 'us-east-2'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_6() {
    // Logging AWS credentials in a template string
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    // ruleid: typescript-do-not-log-aws-credentials
    console.log(`Connecting to AWS with Access Key: ${accessKey} and Secret Key: ${secretKey}`);
    
    const cloudWatch = new AWS.CloudWatch({
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
        region: 'us-west-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_7() {
    // Logging AWS credentials in an array
    const configItems = [
        { name: 'region', value: 'ap-southeast-1' },
        { name: 'accessKeyId', value: 'AKIAIOSFODNN7EXAMPLE' },
        { name: 'secretAccessKey', value: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }
    ];
    
    // ruleid: typescript-do-not-log-aws-credentials
    console.table(configItems);
    
    const sqs = new AWS.SQS({
        accessKeyId: configItems[1].value,
        secretAccessKey: configItems[2].value,
        region: configItems[0].value
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_8() {
    // Logging AWS credentials with string concatenation
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    // ruleid: typescript-do-not-log-aws-credentials
    console.log('AWS Access Key: ' + accessKey + ', Secret Key: ' + secretKey);
    
    const cloudFront = new AWS.CloudFront({
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_9() {
    // Logging AWS credentials in a custom logger
    const customLogger = {
        log: (message: string, ...args: any[]) => {
            const logMessage = `[${new Date().toISOString()}] ${message}`;
            console.log(logMessage, ...args);
            fs.appendFileSync('application.log', logMessage + ' ' + JSON.stringify(args) + '\n');
        }
    };
    
    const awsConfig = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'eu-central-1'
    };
    
    // ruleid: typescript-do-not-log-aws-credentials
    customLogger.log('AWS Configuration:', awsConfig);
    
    const route53 = new AWS.Route53(awsConfig);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_10() {
    // Logging AWS credentials in a conditional block
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const isDebugMode = true;
    
    if (isDebugMode) {
        // ruleid: typescript-do-not-log-aws-credentials
        console.log('Debug - AWS Credentials:', { accessKey, secretKey });
    }
    
    const glacier = new AWS.Glacier({
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
        region: 'us-west-2'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_11() {
    // Logging AWS credentials in a loop
    const regions = ['us-east-1', 'us-west-1', 'eu-west-1'];
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    for (const region of regions) {
        const config = {
            accessKeyId: accessKey,
            secretAccessKey: secretKey,
            region
        };
        
        // ruleid: typescript-do-not-log-aws-credentials
        console.log(`Connecting to region ${region} with config:`, config);
        
        const s3 = new AWS.S3(config);
    }
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_12() {
    // Logging AWS credentials in a try-catch block
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    try {
        const s3 = new AWS.S3({
            accessKeyId: accessKey,
            secretAccessKey: secretKey,
            region: 'us-east-1'
        });
        
        // Some operation
    } catch (error) {
        // ruleid: typescript-do-not-log-aws-credentials
        console.error('Failed with credentials:', { accessKey, secretKey }, error);
    }
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_13() {
    // Logging AWS credentials in a promise chain
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    Promise.resolve()
        .then(() => {
            // ruleid: typescript-do-not-log-aws-credentials
            console.log('Initializing with credentials:', { accessKey, secretKey });
            
            return new AWS.S3({
                accessKeyId: accessKey,
                secretAccessKey: secretKey,
                region: 'us-east-1'
            });
        })
        .catch(error => {
            console.error('Error:', error);
        });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_14() {
    // Logging AWS credentials with destructuring
    const config = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-west-2'
    };
    
    const { accessKeyId, secretAccessKey, region } = config;
    
    // ruleid: typescript-do-not-log-aws-credentials
    console.log('Using AWS credentials:', { accessKeyId, secretAccessKey, region });
    
    const dynamodb = new AWS.DynamoDB({ accessKeyId, secretAccessKey, region });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_15() {
    // Logging AWS credentials in an async function
    async function connectToAWS() {
        const accessKey = 'AKIAIOSFODNN7EXAMPLE';
        const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        
        // ruleid: typescript-do-not-log-aws-credentials
        console.log('Connecting with credentials:', { accessKey, secretKey });
        
        const s3 = new AWS.S3({
            accessKeyId: accessKey,
            secretAccessKey: secretKey,
            region: 'us-east-1'
        });
        
        return s3;
    }
    
    connectToAWS().catch(console.error);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_1() {
    // Using environment variables for AWS credentials
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('Connecting to AWS with credentials from environment variables');
    
    const s3 = new AWS.S3({
        accessKeyId,
        secretAccessKey,
        region: 'us-west-2'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_2() {
    // Using AWS SDK's default credential provider chain
    // ok: typescript-do-not-log-aws-credentials
    console.log('Initializing AWS S3 with default credential provider chain');
    
    const s3 = new AWS.S3({
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_3() {
    // Logging non-sensitive parts of AWS configuration
    const config = {
        region: 'us-west-2',
        apiVersion: '2006-03-01',
        maxRetries: 3
    };
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('AWS Configuration:', config);
    
    const s3 = new AWS.S3({
        ...config,
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_4() {
    // Using AWS credentials file
    // ok: typescript-do-not-log-aws-credentials
    console.log('Loading AWS configuration from credentials file');
    
    const credentials = new AWS.SharedIniFileCredentials({ profile: 'default' });
    const s3 = new AWS.S3({
        credentials,
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_5() {
    // Masking AWS credentials in logs
    const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
    const secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('AWS Access Key ID:', accessKeyId.substring(0, 5) + '...');
    
    const s3 = new AWS.S3({
        accessKeyId,
        secretAccessKey,
        region: 'us-west-2'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_6() {
    // Using a secure credential management system
    function getSecureCredentials() {
        // This would retrieve credentials from a secure vault like AWS Secrets Manager
        return {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
        };
    }
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('Retrieving AWS credentials from secure credential management system');
    
    const credentials = getSecureCredentials();
    const dynamodb = new AWS.DynamoDB({
        ...credentials,
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_7() {
    // Using AWS IAM roles for EC2 instances
    // ok: typescript-do-not-log-aws-credentials
    console.log('Using IAM role credentials for AWS services');
    
    const s3 = new AWS.S3({
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_8() {
    // Using temporary credentials from AWS STS
    // ok: typescript-do-not-log-aws-credentials
    console.log('Obtaining temporary credentials from AWS STS');
    
    const sts = new AWS.STS();
    sts.assumeRole({
        RoleArn: 'arn:aws:iam::123456789012:role/demo-role',
        RoleSessionName: 'demo-session'
    }, (err, data) => {
        if (err) {
            console.error('Error assuming role:', err);
            return;
        }
        
        const tempCredentials = {
            accessKeyId: data.Credentials.AccessKeyId,
            secretAccessKey: data.Credentials.SecretAccessKey,
            sessionToken: data.Credentials.SessionToken
        };
        
        // ok: typescript-do-not-log-aws-credentials
        console.log('Temporary credentials obtained successfully');
        
        const s3 = new AWS.S3({
            ...tempCredentials,
            region: 'us-east-1'
        });
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_9() {
    // Using dotenv to load environment variables
    dotenv.config();
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('AWS configuration loaded from .env file');
    
    const s3 = new AWS.S3({
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        region: process.env.AWS_REGION
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_10() {
    // Logging AWS operation results without credentials
    const s3 = new AWS.S3({
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        region: 'us-east-1'
    });
    
    s3.listBuckets((err, data) => {
        if (err) {
            console.error('Error listing buckets:', err);
            return;
        }
        
        // ok: typescript-do-not-log-aws-credentials
        console.log('S3 buckets:', data.Buckets.map(bucket => bucket.Name));
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_11() {
    // Using a logger with redaction
    const logger = winston.createLogger({
        level: 'info',
        format: winston.format.combine(
            winston.format((info) => {
                // Redact sensitive information
                if (info.aws && info.aws.secretAccessKey) {
                    info.aws.secretAccessKey = '[REDACTED]';
                }
                if (info.aws && info.aws.accessKeyId) {
                    info.aws.accessKeyId = '[REDACTED]';
                }
                return info;
            })(),
            winston.format.json()
        ),
        transports: [
            new winston.transports.Console()
        ]
    });
    
    const awsConfig = {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        region: 'us-east-1'
    };
    
    // ok: typescript-do-not-log-aws-credentials
    logger.info('AWS Configuration:', { aws: awsConfig });
    
    const s3 = new AWS.S3(awsConfig);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_12() {
    // Using AWS SDK with a credential provider
    class CustomCredentialProvider implements AWS.Credentials {
        accessKeyId: string;
        secretAccessKey: string;
        sessionToken?: string;
        
        constructor() {
            this.accessKeyId = process.env.AWS_ACCESS_KEY_ID || '';
            this.secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY || '';
            this.sessionToken = process.env.AWS_SESSION_TOKEN;
        }
        
        get expired(): boolean {
            return false;
        }
        
        refreshPromise(): Promise<void> {
            return Promise.resolve();
        }
        
        refresh(callback: (err?: AWS.AWSError) => void): void {
            callback();
        }
    }
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('Using custom credential provider for AWS');
    
    const credentials = new CustomCredentialProvider();
    const s3 = new AWS.S3({
        credentials,
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_13() {
    // Using AWS SDK with a configuration object that doesn't contain credentials
    const config = {
        region: 'us-east-1',
        maxRetries: 3,
        httpOptions: {
            timeout: 5000
        }
    };
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('AWS Configuration:', config);
    
    // Credentials are loaded from environment variables or credential file
    const s3 = new AWS.S3(config);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_14() {
    // Encrypting sensitive information before logging
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID || '';
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY || '';
    
    function encryptSensitiveData(data: string): string {
        const cipher = crypto.createCipher('aes-256-cbc', 'encryption-key');
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }
    
    const encryptedAccessKey = encryptSensitiveData(accessKeyId);
    const encryptedSecretKey = encryptSensitiveData(secretAccessKey);
    
    // ok: typescript-do-not-log-aws-credentials
    console.log('Encrypted AWS credentials:', {
        accessKeyId: encryptedAccessKey,
        secretAccessKey: encryptedSecretKey
    });
    
    const s3 = new AWS.S3({
        accessKeyId,
        secretAccessKey,
        region: 'us-east-1'
    });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_15() {
    // Using AWS SDK with assumed role credentials
    // ok: typescript-do-not-log-aws-credentials
    console.log('Initializing AWS services with assumed role');
    
    const credentials = new AWS.ChainableTemporaryCredentials({
        params: {
            RoleArn: 'arn:aws:iam::123456789012:role/my-role',
            RoleSessionName: 'my-session'
        }
    });
    
    const s3 = new AWS.S3({
        credentials,
        region: 'us-east-1'
    });
}
// {/fact}