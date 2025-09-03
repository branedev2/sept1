import * as AWS from 'aws-sdk';
import { S3ClientConfig, S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import * as crypto from 'crypto';
import { Request, Response } from 'express';
import * as fs from 'fs';

// TRUE POSITIVES - Vulnerable cases where encryption is conditionally applied

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const s3 = new AWS.S3();
  const isProduction = process.env.NODE_ENV === 'production';
  
  const params = {
    Bucket: 'my-bucket',
    Key: 'sensitive-data.txt',
    Body: 'This contains PII data',
    // ruleid: typescript-s3-partial-encrypt
    ...(isProduction ? { ServerSideEncryption: 'AES256' } : {})
  };
  
  s3.putObject(params, (err, data) => {
    if (err) console.error(err);
    else console.log('File uploaded successfully');
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
  const s3 = new AWS.S3();
  const shouldEncrypt = req.query.encrypt === 'true';
  
  const uploadParams = {
    Bucket: 'customer-data',
    Key: `user-${req.params.userId}.json`,
    Body: JSON.stringify(req.body),
    // ruleid: typescript-s3-partial-encrypt
    ...(shouldEncrypt ? { ServerSideEncryption: 'AES256' } : {})
  };
  
  s3.upload(uploadParams, (err, data) => {
    if (err) res.status(500).send(err);
    else res.status(200).send(data);
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const s3Client = new S3Client({ region: 'us-west-2' });
  const fileType = 'financial';
  
  const command = new PutObjectCommand({
    Bucket: 'company-records',
    Key: 'quarterly-report.pdf',
    Body: fs.createReadStream('./report.pdf'),
    // ruleid: typescript-s3-partial-encrypt
    ...(fileType === 'financial' ? { ServerSideEncryption: 'aws:kms', SSEKMSKeyId: 'arn:aws:kms:us-west-2:111122223333:key/key-id' } : {})
  });
  
  s3Client.send(command);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const s3 = new AWS.S3();
  const userRole = 'standard';
  
  const params = {
    Bucket: 'app-backups',
    Key: 'database-dump.sql',
    Body: 'database content here',
    // ruleid: typescript-s3-partial-encrypt
    ServerSideEncryption: userRole === 'admin' ? 'AES256' : undefined
  };
  
  s3.putObject(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const s3 = new AWS.S3();
  const dataClassification = 'internal';
  
  const uploadParams = {
    Bucket: 'corporate-files',
    Key: 'strategic-plan.docx',
    Body: fs.readFileSync('./strategic-plan.docx'),
    ContentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    // ruleid: typescript-s3-partial-encrypt
    ServerSideEncryption: dataClassification === 'confidential' ? 'AES256' : null
  };
  
  s3.upload(uploadParams);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const s3Client = new S3Client({ region: 'eu-central-1' });
  const isEncryptionRequired = false;
  
  const uploadCommand = new PutObjectCommand({
    Bucket: 'user-uploads',
    Key: 'profile-picture.jpg',
    Body: fs.readFileSync('./profile.jpg'),
    // ruleid: typescript-s3-partial-encrypt
    ...(isEncryptionRequired && { ServerSideEncryption: 'AES256' })
  });
  
  s3Client.send(uploadCommand);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const s3 = new AWS.S3();
  const encryptionConfig = process.env.ENCRYPTION_ENABLED === '1' ? 
    { ServerSideEncryption: 'aws:kms', SSEKMSKeyId: process.env.KMS_KEY_ID } : 
    {};
  
  // ruleid: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'payment-data',
    Key: 'transactions.csv',
    Body: 'transaction data',
    ...encryptionConfig
  };
  
  s3.putObject(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const s3 = new AWS.S3();
  const config = {
    enableEncryption: Math.random() > 0.5, // Randomly decide whether to encrypt
  };
  
  // ruleid: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'random-data',
    Key: 'may-be-encrypted.txt',
    Body: 'some data',
    ServerSideEncryption: config.enableEncryption ? 'AES256' : undefined
  };
  
  s3.upload(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
  const s3Client = new S3Client({ region: 'us-east-1' });
  const tier = req.user?.subscriptionTier || 'free';
  
  // ruleid: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'user-documents',
    Key: `${req.user.id}/document.pdf`,
    Body: req.file.buffer,
    ServerSideEncryption: tier === 'premium' ? 'AES256' : undefined
  });
  
  s3Client.send(command);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const s3 = new AWS.S3();
  const environment = process.env.ENVIRONMENT || 'development';
  
  function uploadFile(fileContent: string, fileName: string) {
    // ruleid: typescript-s3-partial-encrypt
    const params = {
      Bucket: 'app-files',
      Key: fileName,
      Body: fileContent,
      ...(environment === 'production' && { ServerSideEncryption: 'AES256' })
    };
    
    s3.putObject(params);
  }
  
  uploadFile('sensitive content', 'secrets.txt');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const s3 = new AWS.S3();
  const featureFlags = { encryptUploads: false };
  
  // ruleid: typescript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'feature-flagged-bucket',
    Key: 'data.json',
    Body: JSON.stringify({ secret: 'value' }),
    ServerSideEncryption: featureFlags.encryptUploads ? 'AES256' : undefined
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const s3Client = new S3Client({ region: 'ap-southeast-1' });
  const clientConfig = { requireEncryption: true };
  
  if (process.env.OVERRIDE_ENCRYPTION === 'true') {
    clientConfig.requireEncryption = false;
  }
  
  // ruleid: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'configurable-security',
    Key: 'settings.json',
    Body: '{"app":"settings"}',
    ...(clientConfig.requireEncryption ? { ServerSideEncryption: 'AES256' } : {})
  });
  
  s3Client.send(command);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const s3 = new AWS.S3();
  const fileSize = fs.statSync('./large-file.bin').size;
  const encryptionThreshold = 1024 * 1024; // 1MB
  
  // ruleid: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'size-dependent',
    Key: 'large-file.bin',
    Body: fs.createReadStream('./large-file.bin'),
    ServerSideEncryption: fileSize > encryptionThreshold ? 'AES256' : undefined
  };
  
  s3.upload(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const s3 = new AWS.S3();
  const currentHour = new Date().getHours();
  const isBusinessHours = currentHour >= 9 && currentHour <= 17;
  
  // ruleid: typescript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'time-dependent',
    Key: 'hourly-backup.zip',
    Body: 'backup data',
    ...(isBusinessHours ? {} : { ServerSideEncryption: 'AES256' })
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const s3Client = new S3Client({ region: 'us-west-1' });
  const fileName = 'user-report.pdf';
  const isSensitiveFile = fileName.includes('user') || fileName.includes('password');
  
  // ruleid: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'content-based-security',
    Key: fileName,
    Body: fs.readFileSync(`./${fileName}`),
    ServerSideEncryption: isSensitiveFile ? 'AES256' : undefined
  });
  
  s3Client.send(command);
}
// {/fact}

// TRUE NEGATIVES - Secure cases where encryption is consistently applied

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const s3 = new AWS.S3();
  const isProduction = process.env.NODE_ENV === 'production';
  
  // ok: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'my-bucket',
    Key: 'sensitive-data.txt',
    Body: 'This contains PII data',
    ServerSideEncryption: 'AES256'
  };
  
  s3.putObject(params, (err, data) => {
    if (err) console.error(err);
    else console.log('File uploaded successfully');
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
  const s3 = new AWS.S3();
  const shouldEncrypt = req.query.encrypt === 'true';
  
  // ok: typescript-s3-partial-encrypt
  const uploadParams = {
    Bucket: 'customer-data',
    Key: `user-${req.params.userId}.json`,
    Body: JSON.stringify(req.body),
    ServerSideEncryption: 'AES256'
  };
  
  s3.upload(uploadParams, (err, data) => {
    if (err) res.status(500).send(err);
    else res.status(200).send(data);
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const s3Client = new S3Client({ region: 'us-west-2' });
  const fileType = 'financial';
  
  // ok: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'company-records',
    Key: 'quarterly-report.pdf',
    Body: fs.createReadStream('./report.pdf'),
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: 'arn:aws:kms:us-west-2:111122223333:key/key-id'
  });
  
  s3Client.send(command);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const s3 = new AWS.S3();
  const userRole = 'standard';
  
  // Different encryption types based on role, but always encrypted
  // ok: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'app-backups',
    Key: 'database-dump.sql',
    Body: 'database content here',
    ServerSideEncryption: userRole === 'admin' ? 'aws:kms' : 'AES256',
    ...(userRole === 'admin' && { SSEKMSKeyId: process.env.ADMIN_KMS_KEY_ID })
  };
  
  s3.putObject(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const s3 = new AWS.S3();
  const dataClassification = 'internal';
  
  // ok: typescript-s3-partial-encrypt
  const uploadParams = {
    Bucket: 'corporate-files',
    Key: 'strategic-plan.docx',
    Body: fs.readFileSync('./strategic-plan.docx'),
    ContentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ServerSideEncryption: 'AES256'
  };
  
  s3.upload(uploadParams);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const s3Client = new S3Client({ region: 'eu-central-1' });
  const isEncryptionRequired = false; // Even if false, we still encrypt
  
  // ok: typescript-s3-partial-encrypt
  const uploadCommand = new PutObjectCommand({
    Bucket: 'user-uploads',
    Key: 'profile-picture.jpg',
    Body: fs.readFileSync('./profile.jpg'),
    ServerSideEncryption: 'AES256'
  });
  
  s3Client.send(uploadCommand);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const s3 = new AWS.S3();
  // Choose encryption type based on environment, but always encrypt
  const kmsKeyId = process.env.KMS_KEY_ID || 'default-key-id';
  
  // ok: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'payment-data',
    Key: 'transactions.csv',
    Body: 'transaction data',
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: kmsKeyId
  };
  
  s3.putObject(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const s3 = new AWS.S3();
  const config = {
    enableKMS: Math.random() > 0.5, // Randomly decide whether to use KMS or AES256
  };
  
  // ok: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'random-data',
    Key: 'always-encrypted.txt',
    Body: 'some data',
    ServerSideEncryption: config.enableKMS ? 'aws:kms' : 'AES256',
    ...(config.enableKMS && { SSEKMSKeyId: process.env.KMS_KEY_ID })
  };
  
  s3.upload(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
  const s3Client = new S3Client({ region: 'us-east-1' });
  const tier = req.user?.subscriptionTier || 'free';
  
  // ok: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'user-documents',
    Key: `${req.user.id}/document.pdf`,
    Body: req.file.buffer,
    ServerSideEncryption: 'AES256'
  });
  
  s3Client.send(command);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const s3 = new AWS.S3();
  const environment = process.env.ENVIRONMENT || 'development';
  
  function uploadFile(fileContent: string, fileName: string) {
    // ok: typescript-s3-partial-encrypt
    const params = {
      Bucket: 'app-files',
      Key: fileName,
      Body: fileContent,
      ServerSideEncryption: environment === 'production' ? 'aws:kms' : 'AES256',
      ...(environment === 'production' && { SSEKMSKeyId: process.env.PROD_KMS_KEY_ID })
    };
    
    s3.putObject(params);
  }
  
  uploadFile('sensitive content', 'secrets.txt');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const s3 = new AWS.S3();
  const featureFlags = { useKMS: false };
  
  // ok: typescript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'feature-flagged-bucket',
    Key: 'data.json',
    Body: JSON.stringify({ secret: 'value' }),
    ServerSideEncryption: featureFlags.useKMS ? 'aws:kms' : 'AES256',
    ...(featureFlags.useKMS && { SSEKMSKeyId: process.env.KMS_KEY_ID })
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const s3Client = new S3Client({ region: 'ap-southeast-1' });
  const clientConfig = { useCustomKey: true };
  
  if (process.env.USE_DEFAULT_KEY === 'true') {
    clientConfig.useCustomKey = false;
  }
  
  // ok: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'configurable-security',
    Key: 'settings.json',
    Body: '{"app":"settings"}',
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: clientConfig.useCustomKey ? process.env.CUSTOM_KMS_KEY_ID : process.env.DEFAULT_KMS_KEY_ID
  });
  
  s3Client.send(command);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const s3 = new AWS.S3();
  const fileSize = fs.statSync('./large-file.bin').size;
  const useHighPerformanceEncryption = fileSize > 1024 * 1024 * 100; // 100MB
  
  // ok: typescript-s3-partial-encrypt
  const params = {
    Bucket: 'size-dependent',
    Key: 'large-file.bin',
    Body: fs.createReadStream('./large-file.bin'),
    ServerSideEncryption: useHighPerformanceEncryption ? 'AES256' : 'aws:kms',
    ...(useHighPerformanceEncryption ? {} : { SSEKMSKeyId: process.env.KMS_KEY_ID })
  };
  
  s3.upload(params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const s3 = new AWS.S3();
  const currentHour = new Date().getHours();
  const isBusinessHours = currentHour >= 9 && currentHour <= 17;
  
  // ok: typescript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'time-dependent',
    Key: 'hourly-backup.zip',
    Body: 'backup data',
    ServerSideEncryption: isBusinessHours ? 'AES256' : 'aws:kms',
    ...(isBusinessHours ? {} : { SSEKMSKeyId: process.env.AFTER_HOURS_KMS_KEY_ID })
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const s3Client = new S3Client({ region: 'us-west-1' });
  const fileName = 'user-report.pdf';
  const isSensitiveFile = fileName.includes('user') || fileName.includes('password');
  
  // ok: typescript-s3-partial-encrypt
  const command = new PutObjectCommand({
    Bucket: 'content-based-security',
    Key: fileName,
    Body: fs.readFileSync(`./${fileName}`),
    ServerSideEncryption: isSensitiveFile ? 'aws:kms' : 'AES256',
    ...(isSensitiveFile && { SSEKMSKeyId: process.env.SENSITIVE_KMS_KEY_ID })
  });
  
  s3Client.send(command);
}
// {/fact}