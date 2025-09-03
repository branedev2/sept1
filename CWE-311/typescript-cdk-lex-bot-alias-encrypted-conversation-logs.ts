import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lex from 'aws-cdk-lib/aws-lex';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';

class LexBotStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }

  // True positive examples (vulnerable/insecure code)

  bad_case_1() {
    // Creating a Lex bot alias without encryption for conversation logs
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias1', {
      botAliasName: 'TestAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'my-bucket',
              logPrefix: 'audio-logs/'
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: 'my-log-group',
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_2() {
    // Creating a Lex bot alias with only text logs but no encryption
    const logGroup = new logs.LogGroup(this, 'LexLogGroup');
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias2', {
      botAliasName: 'ProductionAlias',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_3() {
    // Creating a Lex bot alias with only audio logs but no encryption
    const bucket = new s3.Bucket(this, 'LexAudioLogsBucket');
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias3', {
      botAliasName: 'DevAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'audio/'
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_4() {
    // Creating a Lex bot alias with both audio and text logs but using default encryption
    const bucket = new s3.Bucket(this, 'AudioLogsBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED, // Using S3 managed keys, not CMK
    });
    
    const logGroup = new logs.LogGroup(this, 'TextLogsGroup', {
      // Using default AWS managed key, not CMK
    });
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias4', {
      botAliasName: 'StagingAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'audio-logs/'
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_5() {
    // Creating a Lex bot alias with conversation logs enabled but not specifying encryption
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    const botAlias = new lex.CfnBotAlias(this, 'BotAlias5', {
      botAliasName: 'TestBot',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/testbot',
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_6() {
    // Creating a Lex bot alias with conversation logs using a predefined bucket without CMK
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias6', {
      botAliasName: 'CustomerSupportBot',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'existing-bucket-name',
              logPrefix: 'lex-logs/'
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_7() {
    // Creating a Lex bot alias with conversation logs using a predefined log group without CMK
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias7', {
      botAliasName: 'SalesBot',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/sales',
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_8() {
    // Creating a Lex bot alias with conversation logs using a bucket with server-side encryption but not CMK
    const bucket = new s3.Bucket(this, 'AudioLogsBucket8', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
    });
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias8', {
      botAliasName: 'HelpDeskBot',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'audio-logs/'
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_9() {
    // Creating a Lex bot alias with conversation logs using a log group with retention but no CMK
    const logGroup = new logs.LogGroup(this, 'TextLogsGroup9', {
      retention: logs.RetentionDays.ONE_WEEK,
    });
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias9', {
      botAliasName: 'MarketingBot',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_10() {
    // Creating multiple Lex bot aliases with conversation logs but no CMK
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias10a', {
      botAliasName: 'DevBot',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/dev',
            }
          },
          enabled: true
        }]
      }
    });
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias10b', {
      botAliasName: 'ProdBot',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'prod-audio-logs',
              logPrefix: 'audio/'
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_11() {
    // Creating a Lex bot alias with conversation logs but using AWS managed key (not customer managed)
    const bucket = new s3.Bucket(this, 'AudioLogsBucket11', {
      encryption: s3.BucketEncryption.KMS, // Using default AWS managed KMS key
    });
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias11', {
      botAliasName: 'FinanceBot',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'finance-bot/'
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_12() {
    // Creating a Lex bot alias with conversation logs but using AWS managed key for CloudWatch logs
    const logGroup = new logs.LogGroup(this, 'TextLogsGroup12', {
      // Using default AWS managed key
    });
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias12', {
      botAliasName: 'HRBot',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_13() {
    // Creating a Lex bot alias with conversation logs using imported resources without CMK
    const importedBucket = s3.Bucket.fromBucketName(this, 'ImportedBucket', 'existing-bucket');
    const importedLogGroup = logs.LogGroup.fromLogGroupName(this, 'ImportedLogGroup', 'existing-log-group');
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias13', {
      botAliasName: 'ImportedResourcesBot',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: importedBucket.bucketName,
              logPrefix: 'imported/'
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: importedLogGroup.logGroupName,
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_14() {
    // Creating a Lex bot alias with conversation logs using a bucket with default encryption
    const bucket = new s3.Bucket(this, 'AudioLogsBucket14');
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias14', {
      botAliasName: 'DefaultEncryptionBot',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'default-encryption/'
            }
          },
          enabled: true
        }]
      }
    });
  }

  bad_case_15() {
    // Creating a Lex bot alias with conversation logs using a log group with default settings
    const logGroup = new logs.LogGroup(this, 'TextLogsGroup15');
    
    // ruleid: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'BotAlias15', {
      botAliasName: 'DefaultSettingsBot',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
            }
          },
          enabled: true
        }]
      }
    });
  }

  // True negative examples (secure code)

  good_case_1() {
    // Creating a Lex bot alias with CMK-encrypted conversation logs for both audio and text
    const key = new kms.Key(this, 'LexLogEncryptionKey1', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    const bucket = new s3.Bucket(this, 'LexAudioLogsBucket1', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key,
    });
    
    const logGroup = new logs.LogGroup(this, 'LexTextLogGroup1', {
      encryptionKey: key,
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias1', {
      botAliasName: 'SecureAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'audio-logs/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
              cloudWatchEncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_2() {
    // Creating a Lex bot alias with CMK-encrypted conversation logs for text only
    const key = new kms.Key(this, 'LexLogEncryptionKey2', {
      enableKeyRotation: true,
      description: 'KMS key for Lex text logs encryption',
    });
    
    const logGroup = new logs.LogGroup(this, 'LexTextLogGroup2', {
      encryptionKey: key,
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias2', {
      botAliasName: 'TextSecureAlias',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
              cloudWatchEncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_3() {
    // Creating a Lex bot alias with CMK-encrypted conversation logs for audio only
    const key = new kms.Key(this, 'LexLogEncryptionKey3', {
      enableKeyRotation: true,
      description: 'KMS key for Lex audio logs encryption',
    });
    
    const bucket = new s3.Bucket(this, 'LexAudioLogsBucket3', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key,
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias3', {
      botAliasName: 'AudioSecureAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'secure-audio/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_4() {
    // Creating a Lex bot alias with separate CMK keys for audio and text logs
    const audioKey = new kms.Key(this, 'AudioLogEncryptionKey', {
      enableKeyRotation: true,
      description: 'KMS key for Lex audio logs encryption',
    });
    
    const textKey = new kms.Key(this, 'TextLogEncryptionKey', {
      enableKeyRotation: true,
      description: 'KMS key for Lex text logs encryption',
    });
    
    const bucket = new s3.Bucket(this, 'LexAudioLogsBucket4', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: audioKey,
    });
    
    const logGroup = new logs.LogGroup(this, 'LexTextLogGroup4', {
      encryptionKey: textKey,
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias4', {
      botAliasName: 'DualKeyAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'dual-key-audio/',
              s3EncryptionKmsKeyId: audioKey.keyId
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
              cloudWatchEncryptionKmsKeyId: textKey.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_5() {
    // Creating a Lex bot alias with imported CMK for conversation logs
    const importedKey = kms.Key.fromKeyArn(this, 'ImportedKey', 
      'arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab');
    
    const bucket = new s3.Bucket(this, 'LexAudioLogsBucket5', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: importedKey,
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias5', {
      botAliasName: 'ImportedKeyAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'imported-key-audio/',
              s3EncryptionKmsKeyId: importedKey.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_6() {
    // Creating a Lex bot alias with CMK encryption and additional security settings
    const key = new kms.Key(this, 'LexLogEncryptionKey6', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
      pendingWindow: cdk.Duration.days(7),
    });
    
    const bucket = new s3.Bucket(this, 'LexAudioLogsBucket6', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
    });
    
    const logGroup = new logs.LogGroup(this, 'LexTextLogGroup6', {
      encryptionKey: key,
      retention: logs.RetentionDays.ONE_MONTH,
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias6', {
      botAliasName: 'EnhancedSecurityAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: bucket.bucketName,
              logPrefix: 'enhanced-security/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: logGroup.logGroupName,
              cloudWatchEncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_7() {
    // Creating a Lex bot alias with CMK encryption using key ID directly
    const key = new kms.Key(this, 'LexLogEncryptionKey7', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias7', {
      botAliasName: 'DirectKeyIdAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'existing-secure-bucket',
              logPrefix: 'direct-key-id/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/secure-logs',
              cloudWatchEncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_8() {
    // Creating a Lex bot alias with CMK encryption using key ARN directly
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias8', {
      botAliasName: 'KeyArnAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'existing-secure-bucket',
              logPrefix: 'key-arn/',
              s3EncryptionKmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab'
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/secure-text-logs',
              cloudWatchEncryptionKmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab'
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_9() {
    // Creating a Lex bot alias with multiple CMK-encrypted audio log destinations
    const key = new kms.Key(this, 'LexLogEncryptionKey9', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias9', {
      botAliasName: 'MultiDestinationAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [
          {
            destination: {
              s3Bucket: {
                s3BucketName: 'primary-audio-bucket',
                logPrefix: 'primary/',
                s3EncryptionKmsKeyId: key.keyId
              }
            },
            enabled: true
          },
          {
            destination: {
              s3Bucket: {
                s3BucketName: 'backup-audio-bucket',
                logPrefix: 'backup/',
                s3EncryptionKmsKeyId: key.keyId
              }
            },
            enabled: true
          }
        ]
      }
    });
  }

  good_case_10() {
    // Creating a Lex bot alias with CMK encryption and conditional logging
    const key = new kms.Key(this, 'LexLogEncryptionKey10', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias10', {
      botAliasName: 'ConditionalLoggingAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'conditional-audio-bucket',
              logPrefix: 'conditional/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/conditional-text-logs',
              cloudWatchEncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      },
      sentimentAnalysisSettings: {
        detectSentiment: true
      }
    });
  }

  good_case_11() {
    // Creating a Lex bot alias with CMK encryption and bot version settings
    const key = new kms.Key(this, 'LexLogEncryptionKey11', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias11', {
      botAliasName: 'VersionedAlias',
      botId: 'botId',
      botVersion: '1',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'versioned-audio-bucket',
              logPrefix: 'v1/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_12() {
    // Creating a Lex bot alias with CMK encryption and description
    const key = new kms.Key(this, 'LexLogEncryptionKey12', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias12', {
      botAliasName: 'DescriptiveAlias',
      botId: 'botId',
      description: 'A secure bot alias with CMK-encrypted conversation logs',
      conversationLogSettings: {
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: '/aws/lex/descriptive-logs',
              cloudWatchEncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_13() {
    // Creating a Lex bot alias with CMK encryption and tags
    const key = new kms.Key(this, 'LexLogEncryptionKey13', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias13', {
      botAliasName: 'TaggedAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: 'tagged-audio-bucket',
              logPrefix: 'tagged/',
              s3EncryptionKmsKeyId: key.keyId
            }
          },
          enabled: true
        }]
      },
      tags: [
        {
          key: 'Environment',
          value: 'Production'
        },
        {
          key: 'SecurityCompliance',
          value: 'HIPAA'
        }
      ]
    });
  }

  good_case_14() {
    // Creating a Lex bot alias with CMK encryption using imported resources
    const importedKey = kms.Key.fromKeyArn(this, 'ImportedKey14', 
      'arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab');
    
    const importedBucket = s3.Bucket.fromBucketName(this, 'ImportedBucket14', 'existing-secure-bucket');
    const importedLogGroup = logs.LogGroup.fromLogGroupName(this, 'ImportedLogGroup14', 'existing-secure-log-group');
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias14', {
      botAliasName: 'ImportedResourcesSecureAlias',
      botId: 'botId',
      conversationLogSettings: {
        audioLogSettings: [{
          destination: {
            s3Bucket: {
              s3BucketName: importedBucket.bucketName,
              logPrefix: 'imported-secure/',
              s3EncryptionKmsKeyId: importedKey.keyId
            }
          },
          enabled: true
        }],
        textLogSettings: [{
          destination: {
            cloudWatch: {
              cloudWatchLogGroupName: importedLogGroup.logGroupName,
              cloudWatchEncryptionKmsKeyId: importedKey.keyId
            }
          },
          enabled: true
        }]
      }
    });
  }

  good_case_15() {
    // Creating a Lex bot alias with CMK encryption and multiple text log destinations
    const key = new kms.Key(this, 'LexLogEncryptionKey15', {
      enableKeyRotation: true,
      description: 'KMS key for Lex conversation logs encryption',
    });
    
    // ok: typescript-cdk-lex-bot-alias-encrypted-conversation-logs
    new lex.CfnBotAlias(this, 'SecureBotAlias15', {
      botAliasName: 'MultiTextLogAlias',
      botId: 'botId',
      conversationLogSettings: {
        textLogSettings: [
          {
            destination: {
              cloudWatch: {
                cloudWatchLogGroupName: '/aws/lex/primary-text-logs',
                cloudWatchEncryptionKmsKeyId: key.keyId
              }
            },
            enabled: true
          },
          {
            destination: {
              cloudWatch: {
                cloudWatchLogGroupName: '/aws/lex/secondary-text-logs',
                cloudWatchEncryptionKmsKeyId: key.keyId
              }
            },
            enabled: true
          }
        ]
      }
    });
  }
}