// File: s3_encryption_examples.js
const AWS = require('aws-sdk');
const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');

// TRUE POSITIVES (Vulnerable code examples)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const s3 = new AWS.S3();
  const userData = { name: "John", ssn: "123-45-6789", address: "123 Main St" };
  
  // Conditional encryption based on environment
  if (process.env.NODE_ENV === 'production') {
    // ruleid: javascript-s3-partial-encrypt
    s3.putObject({
      Bucket: 'user-data-bucket',
      Key: 'user-info.json',
      Body: JSON.stringify(userData),
      ServerSideEncryption: 'AES256'
    }).promise();
  } else {
    // Development environment - no encryption
    s3.putObject({
      Bucket: 'user-data-bucket',
      Key: 'user-info.json',
      Body: JSON.stringify(userData)
    }).promise();
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const s3 = new AWS.S3();
  const creditCardInfo = { number: "4111-1111-1111-1111", expiry: "12/25", cvv: "123" };
  
  // Encryption based on data size
  if (JSON.stringify(creditCardInfo).length > 1000) {
    // ruleid: javascript-s3-partial-encrypt
    s3.upload({
      Bucket: 'payment-data',
      Key: 'card-info.json',
      Body: JSON.stringify(creditCardInfo),
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'
    }).promise();
  } else {
    // Small data - no encryption
    s3.upload({
      Bucket: 'payment-data',
      Key: 'card-info.json',
      Body: JSON.stringify(creditCardInfo)
    }).promise();
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const s3 = new AWS.S3();
  const isEncryptionEnabled = Math.random() > 0.5; // Random decision to encrypt
  
  // ruleid: javascript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'customer-data',
    Key: 'personal-info.json',
    Body: JSON.stringify({ ssn: "987-65-4321", dob: "1980-01-01" }),
    ...(isEncryptionEnabled && { ServerSideEncryption: 'AES256' })
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const s3 = new AWS.S3();
  const userData = { username: "user123", password: "secureP@ss!" };
  
  // Encryption based on user preference
  function saveUserData(encryptData) {
    // ruleid: javascript-s3-partial-encrypt
    if (encryptData) {
      s3.putObject({
        Bucket: 'user-credentials',
        Key: 'login-info.json',
        Body: JSON.stringify(userData),
        ServerSideEncryption: 'AES256'
      }).promise();
    } else {
      s3.putObject({
        Bucket: 'user-credentials',
        Key: 'login-info.json',
        Body: JSON.stringify(userData)
      }).promise();
    }
  }
  
  saveUserData(false); // Called with encryption disabled
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const s3 = new AWS.S3();
  const sensitiveData = { apiKey: "sk_test_abcdefghijklmnopqrstuvwxyz" };
  
  // Encryption based on bucket name
  const bucketName = 'api-keys-' + (process.env.STAGE || 'dev');
  
  // ruleid: javascript-s3-partial-encrypt
  if (bucketName.includes('prod')) {
    s3.upload({
      Bucket: bucketName,
      Key: 'stripe-keys.json',
      Body: JSON.stringify(sensitiveData),
      ServerSideEncryption: 'aws:kms'
    }).promise();
  } else {
    s3.upload({
      Bucket: bucketName,
      Key: 'stripe-keys.json',
      Body: JSON.stringify(sensitiveData)
    }).promise();
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const s3 = new AWS.S3();
  const healthData = { patientId: "12345", diagnosis: "Confidential", medications: ["Med A", "Med B"] };
  
  // Encryption based on feature flag
  axios.get('https://config-server/feature-flags')
    .then(response => {
      const useEncryption = response.data.enableEncryption;
      
      // ruleid: javascript-s3-partial-encrypt
      if (useEncryption) {
        s3.putObject({
          Bucket: 'health-records',
          Key: 'patient-data.json',
          Body: JSON.stringify(healthData),
          ServerSideEncryption: 'AES256'
        }).promise();
      } else {
        s3.putObject({
          Bucket: 'health-records',
          Key: 'patient-data.json',
          Body: JSON.stringify(healthData)
        }).promise();
      }
    });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const s3 = new AWS.S3();
  const employeeData = { id: "E12345", salary: 75000, bankAccount: "9876543210" };
  
  // Encryption based on data type
  function saveEmployeeData(dataType) {
    // ruleid: javascript-s3-partial-encrypt
    if (dataType === 'financial') {
      s3.upload({
        Bucket: 'hr-data',
        Key: 'employee-financial.json',
        Body: JSON.stringify(employeeData),
        ServerSideEncryption: 'AES256'
      }).promise();
    } else {
      s3.upload({
        Bucket: 'hr-data',
        Key: 'employee-general.json',
        Body: JSON.stringify(employeeData)
      }).promise();
    }
  }
  
  saveEmployeeData('general'); // Called with non-financial type
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const s3 = new AWS.S3();
  const documentData = fs.readFileSync('confidential.pdf');
  const documentSize = documentData.length;
  
  // Encryption based on file size
  // ruleid: javascript-s3-partial-encrypt
  if (documentSize > 5 * 1024 * 1024) { // 5MB
    s3.putObject({
      Bucket: 'legal-documents',
      Key: 'confidential.pdf',
      Body: documentData,
      ServerSideEncryption: 'aws:kms'
    }).promise();
  } else {
    s3.putObject({
      Bucket: 'legal-documents',
      Key: 'confidential.pdf',
      Body: documentData
    }).promise();
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const s3 = new AWS.S3();
  const backupData = { dbDump: "base64encodeddata...", timestamp: new Date().toISOString() };
  
  // Encryption based on time of day
  const currentHour = new Date().getHours();
  
  // ruleid: javascript-s3-partial-encrypt
  if (currentHour >= 8 && currentHour <= 17) { // Business hours
    s3.upload({
      Bucket: 'database-backups',
      Key: 'backup-' + new Date().toISOString() + '.json',
      Body: JSON.stringify(backupData),
      ServerSideEncryption: 'AES256'
    }).promise();
  } else {
    s3.upload({
      Bucket: 'database-backups',
      Key: 'backup-' + new Date().toISOString() + '.json',
      Body: JSON.stringify(backupData)
    }).promise();
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const s3 = new AWS.S3();
  const configData = { dbPassword: "db_p@ssw0rd!", apiKey: "api_key_12345" };
  
  // Encryption based on user role
  function saveConfigData(userRole) {
    // ruleid: javascript-s3-partial-encrypt
    switch (userRole) {
      case 'admin':
        s3.putObject({
          Bucket: 'app-config',
          Key: 'secrets.json',
          Body: JSON.stringify(configData),
          ServerSideEncryption: 'AES256'
        }).promise();
        break;
      default:
        s3.putObject({
          Bucket: 'app-config',
          Key: 'secrets.json',
          Body: JSON.stringify(configData)
        }).promise();
        break;
    }
  }
  
  saveConfigData('user'); // Called with non-admin role
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const s3 = new AWS.S3();
  const customerData = { id: "C12345", creditScore: 750, income: 85000 };
  
  // Encryption based on customer tier
  function saveCustomerData(customerTier) {
    // ruleid: javascript-s3-partial-encrypt
    if (customerTier === 'premium') {
      s3.upload({
        Bucket: 'customer-analytics',
        Key: 'customer-' + customerData.id + '.json',
        Body: JSON.stringify(customerData),
        ServerSideEncryption: 'aws:kms'
      }).promise();
    } else {
      s3.upload({
        Bucket: 'customer-analytics',
        Key: 'customer-' + customerData.id + '.json',
        Body: JSON.stringify(customerData)
      }).promise();
    }
  }
  
  saveCustomerData('basic'); // Called with basic tier
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const s3 = new AWS.S3();
  const logData = { userActions: ["login", "view-account", "change-password"], timestamp: new Date().toISOString() };
  
  // Encryption based on log level
  function saveLogData(logLevel) {
    // ruleid: javascript-s3-partial-encrypt
    if (logLevel === 'security') {
      s3.putObject({
        Bucket: 'application-logs',
        Key: 'security-logs.json',
        Body: JSON.stringify(logData),
        ServerSideEncryption: 'AES256'
      }).promise();
    } else {
      s3.putObject({
        Bucket: 'application-logs',
        Key: 'general-logs.json',
        Body: JSON.stringify(logData)
      }).promise();
    }
  }
  
  saveLogData('general'); // Called with general log level
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const s3 = new AWS.S3();
  const messageData = { sender: "user1", recipient: "user2", content: "Private message content" };
  
  // Encryption based on message type
  function saveMessage(messageType) {
    // ruleid: javascript-s3-partial-encrypt
    if (messageType === 'private') {
      s3.upload({
        Bucket: 'messages',
        Key: 'msg-' + Date.now() + '.json',
        Body: JSON.stringify(messageData),
        ServerSideEncryption: 'AES256'
      }).promise();
    } else {
      s3.upload({
        Bucket: 'messages',
        Key: 'msg-' + Date.now() + '.json',
        Body: JSON.stringify(messageData)
      }).promise();
    }
  }
  
  saveMessage('public'); // Called with public message type
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const s3 = new AWS.S3();
  const researchData = { participantId: "P12345", responses: [5, 3, 4, 2, 5] };
  
  // Encryption based on research consent level
  function saveResearchData(consentLevel) {
    // ruleid: javascript-s3-partial-encrypt
    if (consentLevel === 'full') {
      s3.putObject({
        Bucket: 'research-data',
        Key: 'participant-' + researchData.participantId + '.json',
        Body: JSON.stringify(researchData),
        ServerSideEncryption: 'aws:kms'
      }).promise();
    } else {
      s3.putObject({
        Bucket: 'research-data',
        Key: 'participant-' + researchData.participantId + '.json',
        Body: JSON.stringify(researchData)
      }).promise();
    }
  }
  
  saveResearchData('partial'); // Called with partial consent
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const s3 = new AWS.S3();
  const backupConfig = { frequency: "daily", retention: 30, includePersonalData: true };
  
  // Encryption based on configuration flag
  // ruleid: javascript-s3-partial-encrypt
  if (backupConfig.includePersonalData) {
    s3.upload({
      Bucket: 'system-backups',
      Key: 'backup-config.json',
      Body: JSON.stringify(backupConfig),
      ServerSideEncryption: 'AES256'
    }).promise();
  } else {
    s3.upload({
      Bucket: 'system-backups',
      Key: 'backup-config.json',
      Body: JSON.stringify(backupConfig)
    }).promise();
  }
}
// {/fact}

// TRUE NEGATIVES (Secure code examples)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const s3 = new AWS.S3();
  const userData = { name: "John", ssn: "123-45-6789", address: "123 Main St" };
  
  // Always encrypt sensitive data regardless of environment
  // ok: javascript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'user-data-bucket',
    Key: 'user-info.json',
    Body: JSON.stringify(userData),
    ServerSideEncryption: 'AES256'
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const s3 = new AWS.S3();
  const creditCardInfo = { number: "4111-1111-1111-1111", expiry: "12/25", cvv: "123" };
  
  // Consistent encryption regardless of data size
  // ok: javascript-s3-partial-encrypt
  s3.upload({
    Bucket: 'payment-data',
    Key: 'card-info.json',
    Body: JSON.stringify(creditCardInfo),
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const s3 = new AWS.S3();
  
  // Always enable encryption, no conditional logic
  // ok: javascript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'customer-data',
    Key: 'personal-info.json',
    Body: JSON.stringify({ ssn: "987-65-4321", dob: "1980-01-01" }),
    ServerSideEncryption: 'AES256'
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const s3 = new AWS.S3();
  const userData = { username: "user123", password: "secureP@ss!" };
  
  // Encryption not dependent on user preference
  function saveUserData(metadata) {
    // ok: javascript-s3-partial-encrypt
    s3.putObject({
      Bucket: 'user-credentials',
      Key: 'login-info.json',
      Body: JSON.stringify(userData),
      Metadata: metadata,
      ServerSideEncryption: 'AES256'
    }).promise();
  }
  
  saveUserData({ userType: 'standard' });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const s3 = new AWS.S3();
  const sensitiveData = { apiKey: "sk_test_abcdefghijklmnopqrstuvwxyz" };
  
  // Encryption regardless of bucket name
  const bucketName = 'api-keys-' + (process.env.STAGE || 'dev');
  
  // ok: javascript-s3-partial-encrypt
  s3.upload({
    Bucket: bucketName,
    Key: 'stripe-keys.json',
    Body: JSON.stringify(sensitiveData),
    ServerSideEncryption: 'aws:kms'
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const s3 = new AWS.S3();
  const healthData = { patientId: "12345", diagnosis: "Confidential", medications: ["Med A", "Med B"] };
  
  // Encryption regardless of feature flag
  axios.get('https://config-server/feature-flags')
    .then(response => {
      const additionalTags = response.data.enableTags ? { Tags: [{ Key: 'Confidential', Value: 'true' }] } : {};
      
      // ok: javascript-s3-partial-encrypt
      s3.putObject({
        Bucket: 'health-records',
        Key: 'patient-data.json',
        Body: JSON.stringify(healthData),
        ServerSideEncryption: 'AES256',
        ...additionalTags
      }).promise();
    });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const s3 = new AWS.S3();
  const employeeData = { id: "E12345", salary: 75000, bankAccount: "9876543210" };
  
  // Encryption regardless of data type
  function saveEmployeeData(dataType) {
    const keyPrefix = dataType === 'financial' ? 'financial/' : 'general/';
    
    // ok: javascript-s3-partial-encrypt
    s3.upload({
      Bucket: 'hr-data',
      Key: keyPrefix + 'employee-data.json',
      Body: JSON.stringify(employeeData),
      ServerSideEncryption: 'AES256'
    }).promise();
  }
  
  saveEmployeeData('general');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const s3 = new AWS.S3();
  const documentData = fs.readFileSync('confidential.pdf');
  const documentSize = documentData.length;
  
  // Encryption regardless of file size
  let storageClass;
  if (documentSize > 5 * 1024 * 1024) { // 5MB
    storageClass = 'STANDARD_IA';
  } else {
    storageClass = 'STANDARD';
  }
  
  // ok: javascript-s3-partial-encrypt
  s3.putObject({
    Bucket: 'legal-documents',
    Key: 'confidential.pdf',
    Body: documentData,
    StorageClass: storageClass,
    ServerSideEncryption: 'aws:kms'
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const s3 = new AWS.S3();
  const backupData = { dbDump: "base64encodeddata...", timestamp: new Date().toISOString() };
  
  // Encryption regardless of time of day
  const currentHour = new Date().getHours();
  const priority = (currentHour >= 8 && currentHour <= 17) ? 'high' : 'low';
  
  // ok: javascript-s3-partial-encrypt
  s3.upload({
    Bucket: 'database-backups',
    Key: 'backup-' + new Date().toISOString() + '.json',
    Body: JSON.stringify(backupData),
    Metadata: { priority },
    ServerSideEncryption: 'AES256'
  }).promise();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const s3 = new AWS.S3();
  const configData = { dbPassword: "db_p@ssw0rd!", apiKey: "api_key_12345" };
  
  // Encryption regardless of user role
  function saveConfigData(userRole) {
    const metadata = { role: userRole };
    
    // ok: javascript-s3-partial-encrypt
    s3.putObject({
      Bucket: 'app-config',
      Key: 'secrets.json',
      Body: JSON.stringify(configData),
      Metadata: metadata,
      ServerSideEncryption: 'AES256'
    }).promise();
  }
  
  saveConfigData('user');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const s3 = new AWS.S3();
  const customerData = { id: "C12345", creditScore: 750, income: 85000 };
  
  // Encryption regardless of customer tier
  function saveCustomerData(customerTier) {
    const keyPrefix = customerTier === 'premium' ? 'premium/' : 'basic/';
    
    // ok: javascript-s3-partial-encrypt
    s3.upload({
      Bucket: 'customer-analytics',
      Key: keyPrefix + 'customer-' + customerData.id + '.json',
      Body: JSON.stringify(customerData),
      ServerSideEncryption: 'aws:kms'
    }).promise();
  }
  
  saveCustomerData('basic');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const s3 = new AWS.S3();
  const logData = { userActions: ["login", "view-account", "change-password"], timestamp: new Date().toISOString() };
  
  // Encryption regardless of log level
  function saveLogData(logLevel) {
    const logKey = logLevel === 'security' ? 'security-logs.json' : 'general-logs.json';
    
    // ok: javascript-s3-partial-encrypt
    s3.putObject({
      Bucket: 'application-logs',
      Key: logKey,
      Body: JSON.stringify(logData),
      ServerSideEncryption: 'AES256'
    }).promise();
  }
  
  saveLogData('general');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const s3 = new AWS.S3();
  const messageData = { sender: "user1", recipient: "user2", content: "Private message content" };
  
  // Encryption regardless of message type
  function saveMessage(messageType) {
    const isPrivate = messageType === 'private';
    
    // ok: javascript-s3-partial-encrypt
    s3.upload({
      Bucket: 'messages',
      Key: (isPrivate ? 'private/' : 'public/') + 'msg-' + Date.now() + '.json',
      Body: JSON.stringify(messageData),
      ServerSideEncryption: 'AES256'
    }).promise();
  }
  
  saveMessage('public');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const s3 = new AWS.S3();
  const researchData = { participantId: "P12345", responses: [5, 3, 4, 2, 5] };
  
  // Encryption regardless of research consent level
  function saveResearchData(consentLevel) {
    // ok: javascript-s3-partial-encrypt
    s3.putObject({
      Bucket: 'research-data',
      Key: consentLevel + '/participant-' + researchData.participantId + '.json',
      Body: JSON.stringify(researchData),
      ServerSideEncryption: 'aws:kms',
      Metadata: { consentLevel }
    }).promise();
  }
  
  saveResearchData('partial');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const s3 = new AWS.S3();
  const backupConfig = { frequency: "daily", retention: 30, includePersonalData: true };
  
  // Encryption regardless of configuration flag
  const tags = backupConfig.includePersonalData ? 
    { TagSet: [{ Key: 'ContainsPersonalData', Value: 'true' }] } : 
    { TagSet: [{ Key: 'ContainsPersonalData', Value: 'false' }] };
  
  // ok: javascript-s3-partial-encrypt
  s3.upload({
    Bucket: 'system-backups',
    Key: 'backup-config.json',
    Body: JSON.stringify(backupConfig),
    ServerSideEncryption: 'AES256',
    Tagging: tags
  }).promise();
}
// {/fact}