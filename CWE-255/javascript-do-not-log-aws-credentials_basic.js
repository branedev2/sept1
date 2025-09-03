// AWS Credentials Logging Examples
const AWS = require('aws-sdk');
const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});
const console = global.console;

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_1() {
  // Directly logging AWS credentials in console.log
  const awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
  const awsSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  // ruleid: javascript-do-not-log-aws-credentials
  console.log(`AWS Access Key: ${awsAccessKey}, Secret Key: ${awsSecretKey}`);
  
  const s3 = new AWS.S3({
    accessKeyId: awsAccessKey,
    secretAccessKey: awsSecretKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_2() {
  // Logging AWS credentials in an error message
  try {
    const credentials = {
      accessKeyId: 'AKIAI7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    };
    
    // ruleid: javascript-do-not-log-aws-credentials
    console.error('Failed to connect with credentials:', credentials);
    
    const ec2 = new AWS.EC2(credentials);
  } catch (error) {
    console.error(error);
  }
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_3() {
  // Logging AWS credentials using a logging library
  const awsConfig = {
    region: 'us-west-2',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  };
  
  // ruleid: javascript-do-not-log-aws-credentials
  logger.info('AWS Configuration:', awsConfig);
  
  const dynamodb = new AWS.DynamoDB(awsConfig);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_4() {
  // Logging AWS credentials in a debug statement
  const accessKey = 'AKIAIOSFODNN7EXAMPLE';
  const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  // ruleid: javascript-do-not-log-aws-credentials
  console.debug(`Connecting to AWS with Access Key: ${accessKey} and Secret: ${secretKey}`);
  
  const lambda = new AWS.Lambda({
    accessKeyId: accessKey,
    secretAccessKey: secretKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_5() {
  // Logging AWS credentials in a warning message
  const awsCredentials = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  };
  
  // ruleid: javascript-do-not-log-aws-credentials
  console.warn('Using deprecated AWS credentials:', awsCredentials);
  
  const sns = new AWS.SNS(awsCredentials);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_6() {
  // Logging AWS credentials in a formatted string
  const credentials = {
    key: 'AKIAIOSFODNN7EXAMPLE',
    secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  };
  
  // ruleid: javascript-do-not-log-aws-credentials
  console.log(`AWS Credentials - Access Key: ${credentials.key}, Secret Key: ${credentials.secret}`);
  
  const sqs = new AWS.SQS({
    accessKeyId: credentials.key,
    secretAccessKey: credentials.secret
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_7() {
  // Logging AWS credentials in an object with other information
  const config = {
    region: 'us-east-1',
    credentials: {
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    },
    apiVersion: '2014-11-13'
  };
  
  // ruleid: javascript-do-not-log-aws-credentials
  logger.info('Service configuration:', config);
  
  const cloudwatch = new AWS.CloudWatch(config);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_8() {
  // Logging AWS credentials in a conditional block
  const accessKey = 'AKIAIOSFODNN7EXAMPLE';
  const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  if (process.env.NODE_ENV === 'development') {
    // ruleid: javascript-do-not-log-aws-credentials
    console.log('Development AWS credentials:', { accessKey, secretKey });
  }
  
  const cloudfront = new AWS.CloudFront({
    accessKeyId: accessKey,
    secretAccessKey: secretKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_9() {
  // Logging AWS credentials in a try-catch block
  try {
    const awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
    const awsSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    const route53 = new AWS.Route53({
      accessKeyId: awsAccessKey,
      secretAccessKey: awsSecretKey
    });
    
    // Some operation that might fail
    throw new Error('Connection failed');
  } catch (error) {
    // ruleid: javascript-do-not-log-aws-credentials
    console.error('Error with AWS credentials:', { 
      accessKey: 'AKIAIOSFODNN7EXAMPLE', 
      secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' 
    });
  }
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_10() {
  // Logging AWS credentials using string concatenation
  const accessKey = 'AKIAIOSFODNN7EXAMPLE';
  const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  // ruleid: javascript-do-not-log-aws-credentials
  console.log('AWS Access Key: ' + accessKey + ', Secret Key: ' + secretKey);
  
  const glacier = new AWS.Glacier({
    accessKeyId: accessKey,
    secretAccessKey: secretKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_11() {
  // Logging AWS credentials in a loop
  const regions = ['us-east-1', 'us-west-2', 'eu-west-1'];
  const accessKey = 'AKIAIOSFODNN7EXAMPLE';
  const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  regions.forEach(region => {
    // ruleid: javascript-do-not-log-aws-credentials
    console.log(`Connecting to ${region} with Access Key: ${accessKey}, Secret Key: ${secretKey}`);
    
    const ec2 = new AWS.EC2({
      region,
      accessKeyId: accessKey,
      secretAccessKey: secretKey
    });
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_12() {
  // Logging AWS credentials with setTimeout
  const credentials = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  };
  
  setTimeout(() => {
    // ruleid: javascript-do-not-log-aws-credentials
    logger.info('Delayed logging of AWS credentials:', credentials);
    
    const iam = new AWS.IAM(credentials);
  }, 1000);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_13() {
  // Logging AWS credentials in an arrow function
  const getAwsConfig = () => {
    const config = {
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      region: 'us-east-2'
    };
    
    // ruleid: javascript-do-not-log-aws-credentials
    console.log('AWS Config:', config);
    return config;
  };
  
  const s3 = new AWS.S3(getAwsConfig());
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_14() {
  // Logging AWS credentials in a promise chain
  const accessKey = 'AKIAIOSFODNN7EXAMPLE';
  const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  Promise.resolve()
    .then(() => {
      // ruleid: javascript-do-not-log-aws-credentials
      console.log(`AWS Keys - Access: ${accessKey}, Secret: ${secretKey}`);
      
      return new AWS.Redshift({
        accessKeyId: accessKey,
        secretAccessKey: secretKey
      });
    })
    .catch(console.error);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=1}
function bad_case_15() {
  // Logging AWS credentials with destructuring
  const awsConfig = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'eu-central-1'
  };
  
  const { accessKeyId, secretAccessKey } = awsConfig;
  
  // ruleid: javascript-do-not-log-aws-credentials
  console.log('AWS Keys:', { accessKeyId, secretAccessKey });
  
  const kinesis = new AWS.Kinesis(awsConfig);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_1() {
  // Using environment variables for AWS credentials
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  
  // ok: javascript-do-not-log-aws-credentials
  console.log('Using environment variables for AWS credentials');
  
  const s3 = new AWS.S3({
    accessKeyId,
    secretAccessKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_2() {
  // Logging only non-sensitive parts of AWS configuration
  const awsConfig = {
    region: 'us-west-2',
    apiVersion: '2014-11-13',
    maxRetries: 3
  };
  
  // ok: javascript-do-not-log-aws-credentials
  console.log('AWS Configuration:', awsConfig);
  
  // Credentials loaded from environment variables or AWS credentials file
  const dynamodb = new AWS.DynamoDB(awsConfig);
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_3() {
  // Using AWS SDK's built-in credential management
  // ok: javascript-do-not-log-aws-credentials
  console.log('Initializing AWS services with default credential provider chain');
  
  // AWS SDK will automatically load credentials from environment variables,
  // shared credentials file, or EC2 instance metadata
  const lambda = new AWS.Lambda({ region: 'us-east-1' });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_4() {
  // Masking AWS credentials when logging
  const accessKey = 'AKIAIOSFODNN7EXAMPLE';
  const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  // ok: javascript-do-not-log-aws-credentials
  console.log(`AWS Access Key: ${accessKey.substring(0, 5)}*****, Secret Key: *****`);
  
  const sns = new AWS.SNS({
    accessKeyId: accessKey,
    secretAccessKey: secretKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_5() {
  // Using AWS credentials file
  // ok: javascript-do-not-log-aws-credentials
  console.log('Using credentials from the shared credentials file');
  
  // AWS SDK will load credentials from ~/.aws/credentials
  const sqs = new AWS.SQS({ region: 'us-east-1' });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_6() {
  // Using IAM roles for EC2 instances
  // ok: javascript-do-not-log-aws-credentials
  logger.info('Using IAM role credentials for EC2 instance');
  
  // AWS SDK will automatically use the IAM role attached to the EC2 instance
  const cloudwatch = new AWS.CloudWatch({ region: 'us-west-2' });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_7() {
  // Logging error without exposing credentials
  try {
    const accessKey = 'AKIAIOSFODNN7EXAMPLE';
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    const cloudfront = new AWS.CloudFront({
      accessKeyId: accessKey,
      secretAccessKey: secretKey
    });
    
    throw new Error('Connection failed');
  } catch (error) {
    // ok: javascript-do-not-log-aws-credentials
    console.error('AWS connection error:', error.message);
  }
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_8() {
  // Using AWS Secrets Manager to retrieve credentials
  const AWS = require('aws-sdk');
  const secretsManager = new AWS.SecretsManager({ region: 'us-east-1' });
  
  // ok: javascript-do-not-log-aws-credentials
  console.log('Retrieving credentials from AWS Secrets Manager');
  
  secretsManager.getSecretValue({ SecretId: 'aws-credentials' }, (err, data) => {
    if (err) {
      console.error('Error retrieving secret:', err.message);
      return;
    }
    
    const secret = JSON.parse(data.SecretString);
    const route53 = new AWS.Route53({
      accessKeyId: secret.accessKeyId,
      secretAccessKey: secret.secretAccessKey
    });
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_9() {
  // Using temporary credentials from AWS STS
  const sts = new AWS.STS();
  
  // ok: javascript-do-not-log-aws-credentials
  console.log('Requesting temporary credentials from AWS STS');
  
  sts.assumeRole({
    RoleArn: 'arn:aws:iam::123456789012:role/demo-role',
    RoleSessionName: 'demo-session'
  }, (err, data) => {
    if (err) {
      console.error('Error assuming role:', err.message);
      return;
    }
    
    const glacier = new AWS.Glacier({
      accessKeyId: data.Credentials.AccessKeyId,
      secretAccessKey: data.Credentials.SecretAccessKey,
      sessionToken: data.Credentials.SessionToken
    });
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_10() {
  // Using AWS SDK with a credential provider
  const credentialProvider = new AWS.CredentialProviderChain();
  
  // ok: javascript-do-not-log-aws-credentials
  console.log('Using AWS credential provider chain');
  
  credentialProvider.resolve((err, credentials) => {
    if (err) {
      console.error('Error resolving credentials:', err.message);
      return;
    }
    
    const ec2 = new AWS.EC2({ credentials });
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_11() {
  // Logging only the AWS service configuration, not credentials
  const serviceConfig = {
    region: 'us-east-1',
    apiVersion: '2016-11-15',
    maxRetries: 5
  };
  
  // ok: javascript-do-not-log-aws-credentials
  logger.info('AWS service configuration:', serviceConfig);
  
  // Credentials are loaded separately and not logged
  const accessKey = process.env.AWS_ACCESS_KEY_ID;
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
  
  const iam = new AWS.IAM({
    ...serviceConfig,
    accessKeyId: accessKey,
    secretAccessKey: secretKey
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_12() {
  // Using AWS config file for region and credentials
  // ok: javascript-do-not-log-aws-credentials
  console.log('Loading AWS configuration from config file');
  
  // AWS SDK will load region from ~/.aws/config and credentials from ~/.aws/credentials
  const s3 = new AWS.S3();
  
  s3.listBuckets((err, data) => {
    if (err) {
      console.error('Error listing buckets:', err.message);
      return;
    }
    console.log('Buckets:', data.Buckets.map(bucket => bucket.Name));
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_13() {
  // Using AWS credentials in a secure manner with promises
  // ok: javascript-do-not-log-aws-credentials
  console.log('Initializing AWS services securely');
  
  // Load credentials from environment variables
  const accessKey = process.env.AWS_ACCESS_KEY_ID;
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
  
  const redshift = new AWS.Redshift({
    accessKeyId: accessKey,
    secretAccessKey: secretKey,
    region: 'us-west-2'
  });
  
  redshift.describeClusters({}).promise()
    .then(data => console.log(`Found ${data.Clusters.length} clusters`))
    .catch(err => console.error('Error describing clusters:', err.message));
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_14() {
  // Using AWS SDK with a profile
  // ok: javascript-do-not-log-aws-credentials
  console.log('Using AWS profile from shared credentials file');
  
  const kinesis = new AWS.Kinesis({
    region: 'us-east-1',
    credentials: new AWS.SharedIniFileCredentials({ profile: 'production' })
  });
}
// {/fact}

// {fact rule=improper-credentials-management@v1.0 defects=0}
function good_case_15() {
  // Using a credential helper function that doesn't log credentials
  function getAwsCredentials() {
    // ok: javascript-do-not-log-aws-credentials
    console.log('Retrieving AWS credentials securely');
    
    return {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    };
  }
  
  const elasticbeanstalk = new AWS.ElasticBeanstalk({
    region: 'us-east-1',
    ...getAwsCredentials()
  });
}
// {/fact}