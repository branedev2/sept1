import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as kms from 'aws-cdk-lib/aws-kms';

class TestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic1', {
    displayName: 'Customer subscription topic'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic2');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topicProps: sns.TopicProps = {
    topicName: 'alerts-topic',
    displayName: 'Alerts Topic for Operations'
  };
  const topic = new sns.Topic(stack, 'AlertsTopic', topicProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic4', {
    contentBasedDeduplication: true,
    fifo: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(stack: cdk.Stack) {
  const topicName = 'notifications';
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic5', {
    topicName: topicName
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic6', {
    displayName: 'Customer subscription topic',
    masterKey: undefined
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(stack: cdk.Stack) {
  // Creating topic with explicit encryption disabled
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic7', {
    displayName: 'Customer subscription topic',
    masterKey: null as unknown as kms.IKey
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const props = {
    displayName: 'Notifications Topic'
  };
  const topic = new sns.Topic(stack, 'MyTopic8', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(stack: cdk.Stack) {
  const config = {
    topicName: 'audit-events',
    displayName: 'Audit Events Topic'
  };
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'AuditTopic', config);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(stack: cdk.Stack) {
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic10', {
    displayName: 'Customer subscription topic',
    // Comment about encryption being handled elsewhere
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(stack: cdk.Stack) {
  const topicProps = {};
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic11', topicProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(stack: cdk.Stack) {
  // Using a factory function that doesn't set encryption
  function createTopicProps() {
    return {
      topicName: 'factory-topic',
      displayName: 'Topic created by factory'
    };
  }
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'FactoryTopic', createTopicProps());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(stack: cdk.Stack) {
  // Creating multiple topics without encryption
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic1 = new sns.Topic(stack, 'Topic1');
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic2 = new sns.Topic(stack, 'Topic2');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(stack: cdk.Stack) {
  const environments = ['dev', 'test', 'prod'];
  
  for (const env of environments) {
    // ruleid: typescript_cdk_sns_missing_severside_encryption
    const topic = new sns.Topic(stack, `Topic-${env}`, {
      topicName: `notifications-${env}`
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(stack: cdk.Stack) {
  // Using conditional logic but still missing encryption
  const isProd = process.env.ENV === 'prod';
  
  // ruleid: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'ConditionalTopic', {
    topicName: isProd ? 'prod-notifications' : 'dev-notifications',
    displayName: isProd ? 'Production Notifications' : 'Development Notifications'
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'MyTopicKey');
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic1', {
    displayName: 'Customer subscription topic',
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'MyTopicKey2');
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic2', {
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(stack: cdk.Stack) {
  const key = kms.Key.fromKeyArn(stack, 'ImportedKey', 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012');
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic3', {
    displayName: 'Customer subscription topic',
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'MyTopicKey4');
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic4', {
    contentBasedDeduplication: true,
    fifo: true,
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(stack: cdk.Stack) {
  const topicName = 'notifications';
  const key = new kms.Key(stack, 'MyTopicKey5');
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic5', {
    topicName: topicName,
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(stack: cdk.Stack) {
  // Using AWS managed key for SNS
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic6', {
    displayName: 'Customer subscription topic',
    masterKey: kms.Key.fromLookup(stack, 'SNSKey', { aliasName: 'alias/aws/sns' })
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(stack: cdk.Stack) {
  const key = kms.Key.fromKeyArn(stack, 'ImportedKey7', 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012');
  const topicProps: sns.TopicProps = {
    topicName: 'secure-topic',
    masterKey: key
  };
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'SecureTopic', topicProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'MyTopicKey8', {
    enableKeyRotation: true,
    description: 'KMS key for SNS encryption'
  });
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'MyTopic8', {
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'MyTopicKey9');
  const config = {
    topicName: 'audit-events',
    displayName: 'Audit Events Topic',
    masterKey: key
  };
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'AuditTopic', config);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(stack: cdk.Stack) {
  // Using a factory function to create a key and topic props
  function createSecureTopicProps() {
    const key = new kms.Key(stack, 'FactoryKey');
    return {
      topicName: 'secure-factory-topic',
      displayName: 'Secure Topic created by factory',
      masterKey: key
    };
  }
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'SecureFactoryTopic', createSecureTopicProps());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(stack: cdk.Stack) {
  // Creating multiple topics with encryption
  const key1 = new kms.Key(stack, 'Key1');
  const key2 = new kms.Key(stack, 'Key2');
  
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic1 = new sns.Topic(stack, 'SecureTopic1', {
    masterKey: key1
  });
  
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic2 = new sns.Topic(stack, 'SecureTopic2', {
    masterKey: key2
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(stack: cdk.Stack) {
  const environments = ['dev', 'test', 'prod'];
  
  for (const env of environments) {
    const key = new kms.Key(stack, `Key-${env}`);
    // ok: typescript_cdk_sns_missing_severside_encryption
    const topic = new sns.Topic(stack, `SecureTopic-${env}`, {
      topicName: `secure-notifications-${env}`,
      masterKey: key
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(stack: cdk.Stack) {
  // Using conditional logic with encryption in both branches
  const isProd = process.env.ENV === 'prod';
  
  const key = isProd 
    ? new kms.Key(stack, 'ProdKey', { description: 'Production key with strict permissions' })
    : new kms.Key(stack, 'DevKey', { description: 'Development key' });
  
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'SecureConditionalTopic', {
    topicName: isProd ? 'prod-notifications' : 'dev-notifications',
    displayName: isProd ? 'Production Notifications' : 'Development Notifications',
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(stack: cdk.Stack) {
  // Using imported key by alias
  const key = kms.Key.fromLookup(stack, 'ImportedKeyByAlias', { 
    aliasName: 'alias/my-sns-key' 
  });
  
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'TopicWithAliasKey', {
    displayName: 'Topic using key alias',
    masterKey: key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(stack: cdk.Stack) {
  // Creating a key with specific policy for SNS
  const key = new kms.Key(stack, 'CustomPolicyKey', {
    enableKeyRotation: true,
    description: 'Custom KMS key for SNS with specific policy'
  });
  
  key.addToResourcePolicy(
    new cdk.aws_iam.PolicyStatement({
      actions: ['kms:Decrypt', 'kms:GenerateDataKey*'],
      principals: [new cdk.aws_iam.ServicePrincipal('sns.amazonaws.com')],
      resources: ['*']
    })
  );
  
  // ok: typescript_cdk_sns_missing_severside_encryption
  const topic = new sns.Topic(stack, 'TopicWithCustomKeyPolicy', {
    displayName: 'Topic with custom key policy',
    masterKey: key
  });
}
// {/fact}