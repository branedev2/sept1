import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as kms from 'aws-cdk-lib/aws-kms';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Basic queue without encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'UnencryptedQueue', {
    visibilityTimeout: cdk.Duration.seconds(300)
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Queue with FIFO but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const fifoQueue = new sqs.Queue(scope, 'UnencryptedFifoQueue', {
    fifo: true,
    contentBasedDeduplication: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Queue with dead letter queue but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const deadLetterQueue = new sqs.Queue(scope, 'DeadLetterQueue');
  
  // ruleid: typescript_cdk_sqs_missing_encryption
  const mainQueue = new sqs.Queue(scope, 'MainQueue', {
    deadLetterQueue: {
      queue: deadLetterQueue,
      maxReceiveCount: 3
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Queue with explicit encryption set to false
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'ExplicitlyUnencryptedQueue', {
    encryption: sqs.QueueEncryption.UNENCRYPTED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Queue with high throughput settings but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'HighThroughputQueue', {
    visibilityTimeout: cdk.Duration.seconds(30),
    receiveMessageWaitTime: cdk.Duration.seconds(20),
    retentionPeriod: cdk.Duration.days(7)
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Queue created from imported attributes but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'ImportedQueue', {
    queueName: 'existing-queue-name'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct, stackId: string) {
  // Queue with conditional creation but no encryption
  const condition = stackId === 'prod-stack';
  
  if (condition) {
    // ruleid: typescript_cdk_sqs_missing_encryption
    const queue = new sqs.Queue(scope, 'ConditionalQueue', {
      queueName: 'conditional-queue'
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Queue with delivery delay but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'DelayedDeliveryQueue', {
    deliveryDelay: cdk.Duration.seconds(60)
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Queue with explicit queue URL export but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'ExportedUrlQueue');
  
  new cdk.CfnOutput(scope, 'QueueURL', {
    value: queue.queueUrl,
    exportName: 'MyQueueURL'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Queue with custom queue name but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'CustomNameQueue', {
    queueName: 'my-special-queue'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Queue created in a loop but none with encryption
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript_cdk_sqs_missing_encryption
    const queue = new sqs.Queue(scope, `Queue-${i}`, {
      queueName: `queue-${i}`
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Queue with removalPolicy but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'RemovalPolicyQueue', {
    removalPolicy: cdk.RemovalPolicy.DESTROY
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Queue with tags but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'TaggedQueue');
  
  cdk.Tags.of(queue).add('Environment', 'Production');
  cdk.Tags.of(queue).add('CostCenter', '12345');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const queueProps = {
    visibilityTimeout: cdk.Duration.seconds(300),
    receiveMessageWaitTime: cdk.Duration.seconds(20)
  };
  
  // Queue with props from variable but no encryption
  // ruleid: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'PropVariableQueue', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Queue created with factory pattern but no encryption
  function createQueue(id: string) {
    // ruleid: typescript_cdk_sqs_missing_encryption
    return new sqs.Queue(scope, id, {
      queueName: `${id}-queue`
    });
  }
  
  const queue1 = createQueue('Factory1');
  const queue2 = createQueue('Factory2');
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Queue with KMS-managed encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'KmsEncryptedQueue', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Queue with custom KMS key
  const key = new kms.Key(scope, 'QueueKey', {
    enableKeyRotation: true
  });
  
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'CustomKeyEncryptedQueue', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // FIFO queue with encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const fifoQueue = new sqs.Queue(scope, 'EncryptedFifoQueue', {
    fifo: true,
    contentBasedDeduplication: true,
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Queue with dead letter queue, both encrypted
  // ok: typescript_cdk_sqs_missing_encryption
  const deadLetterQueue = new sqs.Queue(scope, 'EncryptedDLQ', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
  
  // ok: typescript_cdk_sqs_missing_encryption
  const mainQueue = new sqs.Queue(scope, 'EncryptedMainQueue', {
    deadLetterQueue: {
      queue: deadLetterQueue,
      maxReceiveCount: 3
    },
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Queue with high throughput settings and encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedHighThroughputQueue', {
    visibilityTimeout: cdk.Duration.seconds(30),
    receiveMessageWaitTime: cdk.Duration.seconds(20),
    retentionPeriod: cdk.Duration.days(7),
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Queue with custom name and encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedCustomNameQueue', {
    queueName: 'my-encrypted-queue',
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct, stackId: string) {
  // Queue with conditional creation and encryption
  const condition = stackId === 'prod-stack';
  
  if (condition) {
    // ok: typescript_cdk_sqs_missing_encryption
    const queue = new sqs.Queue(scope, 'EncryptedConditionalQueue', {
      queueName: 'conditional-queue',
      encryption: sqs.QueueEncryption.KMS_MANAGED
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Queue with delivery delay and encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedDelayedDeliveryQueue', {
    deliveryDelay: cdk.Duration.seconds(60),
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Queue with URL export and encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedExportedUrlQueue', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
  
  new cdk.CfnOutput(scope, 'EncryptedQueueURL', {
    value: queue.queueUrl,
    exportName: 'MyEncryptedQueueURL'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Queue created in a loop with encryption
  for (let i = 0; i < 3; i++) {
    // ok: typescript_cdk_sqs_missing_encryption
    const queue = new sqs.Queue(scope, `EncryptedQueue-${i}`, {
      queueName: `encrypted-queue-${i}`,
      encryption: sqs.QueueEncryption.KMS_MANAGED
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Queue with removal policy and encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedRemovalPolicyQueue', {
    removalPolicy: cdk.RemovalPolicy.DESTROY,
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Queue with tags and encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedTaggedQueue', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
  
  cdk.Tags.of(queue).add('Environment', 'Production');
  cdk.Tags.of(queue).add('CostCenter', '12345');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const queueProps = {
    visibilityTimeout: cdk.Duration.seconds(300),
    receiveMessageWaitTime: cdk.Duration.seconds(20),
    encryption: sqs.QueueEncryption.KMS_MANAGED
  };
  
  // Queue with props from variable including encryption
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'EncryptedPropVariableQueue', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Queue created with factory pattern with encryption
  function createEncryptedQueue(id: string) {
    // ok: typescript_cdk_sqs_missing_encryption
    return new sqs.Queue(scope, id, {
      queueName: `${id}-queue`,
      encryption: sqs.QueueEncryption.KMS_MANAGED
    });
  }
  
  const queue1 = createEncryptedQueue('SecureFactory1');
  const queue2 = createEncryptedQueue('SecureFactory2');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Queue with imported key for encryption
  const importedKey = kms.Key.fromKeyArn(scope, 'ImportedKey', 
    'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab');
  
  // ok: typescript_cdk_sqs_missing_encryption
  const queue = new sqs.Queue(scope, 'ImportedKeyEncryptedQueue', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: importedKey
  });
}
// {/fact}