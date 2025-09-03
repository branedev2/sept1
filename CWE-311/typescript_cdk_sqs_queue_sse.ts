import * as aws from 'aws-cdk-lib';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Stack, App } from 'aws-cdk-lib';
import { KmsKey } from 'aws-cdk-lib/aws-kms';

// True Positives (Vulnerable Code - Missing Encryption)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue1', {
    queueName: 'my-unencrypted-queue'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue2', {
    visibilityTimeout: aws.Duration.seconds(300),
    receiveMessageWaitTime: aws.Duration.seconds(20)
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue3');
  
  // Even with tags, it's still insecure without encryption
  aws.Tags.of(queue).add('Environment', 'Production');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue4', {
    encryption: sqs.QueueEncryption.UNENCRYPTED // Explicitly disabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const queueProps = {
    fifo: true,
    contentBasedDeduplication: true
  };
  
  // ruleid: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyFifoQueue', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  const deadLetterQueue = new sqs.Queue(stack, 'DeadLetterQueue');
  
  new sqs.Queue(stack, 'MainQueue', {
    deadLetterQueue: {
      maxReceiveCount: 3,
      queue: deadLetterQueue
    },
    encryption: sqs.QueueEncryption.KMS // Main queue is encrypted but DLQ is not
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const queueProps = {};
  
  // ruleid: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue7', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  class CustomStack extends Stack {
    constructor(scope: App, id: string) {
      super(scope, id);
      
      // ruleid: typescript_cdk_sqs_queue_sse
      new sqs.Queue(this, 'MyQueue8', {
        retentionPeriod: aws.Duration.days(7)
      });
    }
  }
  
  const app = new App();
  new CustomStack(app, 'CustomStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue9');
  
  // Adding a subscription doesn't fix the encryption issue
  new aws.sns.Subscription(stack, 'Subscription', {
    endpoint: queue.queueArn,
    protocol: aws.sns.SubscriptionProtocol.SQS,
    topic: new aws.sns.Topic(stack, 'Topic')
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // Creating multiple queues, all unencrypted
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript_cdk_sqs_queue_sse
    new sqs.Queue(stack, `MyQueue${i}`, {
      queueName: `queue-${i}`
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const createQueue = (id: string) => {
    // ruleid: typescript_cdk_sqs_queue_sse
    return new sqs.Queue(stack, id);
  };
  
  const queue = createQueue('MyQueue11');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue12', {
    encryption: undefined // Explicitly set to undefined, which defaults to unencrypted
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const queueProps: sqs.QueueProps = {
    visibilityTimeout: aws.Duration.seconds(30)
  };
  
  if (process.env.NODE_ENV === 'production') {
    queueProps.queueName = 'prod-queue';
  }
  
  // ruleid: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue13', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue14');
  
  // Setting up queue policy but still no encryption
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue]
  });
  
  policy.document.addStatements(
    new aws.iam.PolicyStatement({
      actions: ['sqs:SendMessage'],
      principals: [new aws.iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'ArnEquals': {
          'aws:SourceArn': 'arn:aws:sns:us-east-1:123456789012:MyTopic'
        }
      }
    })
  );
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const encryptionType = process.env.ENCRYPT === 'true' ? 
    sqs.QueueEncryption.KMS : 
    sqs.QueueEncryption.UNENCRYPTED;
  
  // ruleid: typescript_cdk_sqs_queue_sse
  // This is vulnerable because it could be unencrypted
  new sqs.Queue(stack, 'MyQueue15', {
    encryption: encryptionType
  });
}
// {/fact}

// True Negatives (Secure Code - Encryption Enabled)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue1', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue2', {
    encryption: sqs.QueueEncryption.KMS
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const key = new KmsKey(stack, 'MyKey');
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue3', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue4', {
    encryption: sqs.QueueEncryption.SQS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const queueProps = {
    fifo: true,
    contentBasedDeduplication: true,
    encryption: sqs.QueueEncryption.KMS_MANAGED
  };
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyFifoQueue', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_sqs_queue_sse
  const deadLetterQueue = new sqs.Queue(stack, 'DeadLetterQueue', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MainQueue', {
    deadLetterQueue: {
      maxReceiveCount: 3,
      queue: deadLetterQueue
    },
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const queueProps = {
    encryption: sqs.QueueEncryption.KMS
  };
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue7', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  class CustomStack extends Stack {
    constructor(scope: App, id: string) {
      super(scope, id);
      
      // ok: typescript_cdk_sqs_queue_sse
      new sqs.Queue(this, 'MyQueue8', {
        retentionPeriod: aws.Duration.days(7),
        encryption: sqs.QueueEncryption.SQS_MANAGED
      });
    }
  }
  
  const app = new App();
  new CustomStack(app, 'CustomStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const key = new KmsKey(stack, 'CustomKey', {
    enableKeyRotation: true
  });
  
  // ok: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue9', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // Creating multiple queues, all encrypted
  for (let i = 0; i < 3; i++) {
    // ok: typescript_cdk_sqs_queue_sse
    new sqs.Queue(stack, `MyQueue${i}`, {
      queueName: `queue-${i}`,
      encryption: sqs.QueueEncryption.KMS_MANAGED
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const createQueue = (id: string) => {
    // ok: typescript_cdk_sqs_queue_sse
    return new sqs.Queue(stack, id, {
      encryption: sqs.QueueEncryption.SQS_MANAGED
    });
  };
  
  const queue = createQueue('MyQueue11');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // Using a custom KMS key with specific configuration
  const key = new KmsKey(stack, 'QueueKey', {
    enableKeyRotation: true,
    description: 'Custom key for SQS queue encryption',
    alias: 'alias/sqs-queue-key'
  });
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue12', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const queueProps: sqs.QueueProps = {
    visibilityTimeout: aws.Duration.seconds(30),
    encryption: sqs.QueueEncryption.KMS_MANAGED
  };
  
  if (process.env.NODE_ENV === 'production') {
    queueProps.queueName = 'prod-queue';
  }
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue13', queueProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_sqs_queue_sse
  const queue = new sqs.Queue(stack, 'MyQueue14', {
    encryption: sqs.QueueEncryption.KMS_MANAGED
  });
  
  // Setting up queue policy with encryption
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue]
  });
  
  policy.document.addStatements(
    new aws.iam.PolicyStatement({
      actions: ['sqs:SendMessage'],
      principals: [new aws.iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'ArnEquals': {
          'aws:SourceArn': 'arn:aws:sns:us-east-1:123456789012:MyTopic'
        }
      }
    })
  );
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // Always use encryption regardless of environment variables
  const encryptionType = sqs.QueueEncryption.KMS_MANAGED;
  
  // ok: typescript_cdk_sqs_queue_sse
  new sqs.Queue(stack, 'MyQueue15', {
    encryption: encryptionType
  });
}
// {/fact}