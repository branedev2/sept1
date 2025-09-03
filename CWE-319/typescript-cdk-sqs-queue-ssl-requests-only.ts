import * as aws from 'aws-cdk-lib';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

class TestStack extends aws.Stack {
  constructor(scope: Construct, id: string, props?: aws.StackProps) {
    super(scope, id, props);
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue', {
    encryption: sqs.QueueEncryption.KMS_MANAGED,
  });
  
  // No SSL requirement in policy
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Creating a policy but not enforcing SSL
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue],
  });
  
  policy.document.addStatements(
    new iam.PolicyStatement({
      actions: ['sqs:SendMessage'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Creating a policy with explicit condition but not enforcing SSL
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue],
  });
  
  policy.document.addStatements(
    new iam.PolicyStatement({
      actions: ['sqs:SendMessage', 'sqs:ReceiveMessage'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'StringEquals': {
          'aws:SourceVpc': 'vpc-12345'
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Adding policy with incorrect condition key
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureConnection': false // Incorrect key
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Adding policy with incorrect condition value
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false // Incorrect value
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const deadLetterQueue = new sqs.Queue(stack, 'DeadLetterQueue');
  
  const queue = new sqs.Queue(stack, 'MainQueue', {
    deadLetterQueue: {
      queue: deadLetterQueue,
      maxReceiveCount: 3,
    },
  });
  
  // No SSL policy for either queue
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const app = new aws.App();
  const stack = new aws.Stack(app, 'TestStack');
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'QueueWithVisibility', {
    visibilityTimeout: aws.Duration.seconds(30),
    receiveMessageWaitTime: aws.Duration.seconds(20),
  });
  
  // Advanced configuration but missing SSL requirement
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Adding policy with StringNotEquals instead of Bool
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'StringNotEquals': {
          'aws:SecureTransport': 'true' // Wrong condition type
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const fifoQueue = new sqs.Queue(stack, 'FifoQueue', {
    fifo: true,
    contentBasedDeduplication: true,
  });
  
  // FIFO queue without SSL requirement
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'EncryptedQueue', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: new aws.kms.Key(stack, 'Key'),
  });
  
  // KMS encryption but no SSL requirement
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Adding policy with incorrect effect
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW, // Should be DENY for non-SSL
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Creating a policy with incomplete conditions
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue],
  });
  
  policy.document.addStatements(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      // Missing SSL condition entirely
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  class CustomQueueStack extends aws.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
      const queue = new sqs.Queue(this, 'CustomQueue', {
        retentionPeriod: aws.Duration.days(7),
      });
      
      // No SSL policy in custom stack
    }
  }
  
  const app = new aws.App();
  new CustomQueueStack(app, 'CustomQueueStack');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Adding policy with typo in condition key
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransprt': false // Typo in key name
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const stack = new aws.Stack();
  
  // ruleid: typescript-cdk-sqs-queue-ssl-requests-only
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // Adding policy with string instead of boolean
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': "false" // String instead of boolean
        }
      }
    })
  );
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue],
  });
  
  policy.document.addStatements(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue', {
    encryption: sqs.QueueEncryption.KMS_MANAGED,
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const stack = new aws.Stack();
  
  const deadLetterQueue = new sqs.Queue(stack, 'DeadLetterQueue');
  
  // Add SSL requirement to DLQ
  deadLetterQueue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [deadLetterQueue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
  
  const queue = new sqs.Queue(stack, 'MainQueue', {
    deadLetterQueue: {
      queue: deadLetterQueue,
      maxReceiveCount: 3,
    },
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const stack = new aws.Stack();
  
  const fifoQueue = new sqs.Queue(stack, 'FifoQueue', {
    fifo: true,
    contentBasedDeduplication: true,
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  fifoQueue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [fifoQueue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'EncryptedQueue', {
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: new aws.kms.Key(stack, 'Key'),
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const app = new aws.App();
  const stack = new aws.Stack(app, 'TestStack');
  
  const queue = new sqs.Queue(stack, 'QueueWithVisibility', {
    visibilityTimeout: aws.Duration.seconds(30),
    receiveMessageWaitTime: aws.Duration.seconds(20),
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  class SecureQueueStack extends aws.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const queue = new sqs.Queue(this, 'CustomQueue', {
        retentionPeriod: aws.Duration.days(7),
      });
      
      // ok: typescript-cdk-sqs-queue-ssl-requests-only
      queue.addToResourcePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.DENY,
          actions: ['sqs:*'],
          principals: [new iam.AnyPrincipal()],
          resources: [queue.queueArn],
          conditions: {
            'Bool': {
              'aws:SecureTransport': false
            }
          }
        })
      );
    }
  }
  
  const app = new aws.App();
  new SecureQueueStack(app, 'SecureQueueStack');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Using a variable for the policy statement
  const sslPolicy = new iam.PolicyStatement({
    effect: iam.Effect.DENY,
    actions: ['sqs:*'],
    principals: [new iam.AnyPrincipal()],
    resources: [queue.queueArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': false
      }
    }
  });
  
  queue.addToResourcePolicy(sslPolicy);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Adding multiple policy statements including SSL requirement
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sqs:SendMessage'],
      principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:role/MyRole')],
      resources: [queue.queueArn],
    })
  );
  
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  const policy = new sqs.QueuePolicy(stack, 'QueuePolicy', {
    queues: [queue],
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Adding multiple statements to policy document
  policy.document.addStatements(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sqs:SendMessage'],
      principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
      resources: [queue.queueArn],
    }),
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const stack = new aws.Stack();
  
  // Creating multiple queues with SSL requirement
  const queue1 = new sqs.Queue(stack, 'Queue1');
  const queue2 = new sqs.Queue(stack, 'Queue2');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Using a function to apply SSL policy to multiple queues
  const applySslPolicy = (queue: sqs.Queue) => {
    queue.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.DENY,
        actions: ['sqs:*'],
        principals: [new iam.AnyPrincipal()],
        resources: [queue.queueArn],
        conditions: {
          'Bool': {
            'aws:SecureTransport': false
          }
        }
      })
    );
  };
  
  applySslPolicy(queue1);
  applySslPolicy(queue2);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Using a more specific action list
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: [
        'sqs:SendMessage',
        'sqs:ReceiveMessage',
        'sqs:DeleteMessage',
        'sqs:GetQueueAttributes'
      ],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const stack = new aws.Stack();
  
  const queue = new sqs.Queue(stack, 'MyQueue');
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Using a combination of conditions including SSL requirement
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        },
        'StringNotEquals': {
          'aws:SourceVpc': 'vpc-12345'
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const stack = new aws.Stack();
  
  // Creating a queue with all the bells and whistles
  const queue = new sqs.Queue(stack, 'CompleteQueue', {
    visibilityTimeout: aws.Duration.seconds(30),
    receiveMessageWaitTime: aws.Duration.seconds(20),
    deadLetterQueue: {
      queue: new sqs.Queue(stack, 'DeadLetterQueue'),
      maxReceiveCount: 3,
    },
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey: new aws.kms.Key(stack, 'Key'),
    fifo: true,
    contentBasedDeduplication: true,
    retentionPeriod: aws.Duration.days(7),
  });
  
  // ok: typescript-cdk-sqs-queue-ssl-requests-only
  // Comprehensive policy with SSL requirement
  queue.addToResourcePolicy(
    new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['sqs:*'],
      principals: [new iam.AnyPrincipal()],
      resources: [queue.queueArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': false
        }
      }
    })
  );
}
// {/fact}