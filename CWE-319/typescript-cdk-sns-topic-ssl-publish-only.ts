import * as aws from 'aws-cdk-lib';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

class TestStack extends aws.Stack {
  constructor(scope: Construct, id: string, props?: aws.StackProps) {
    super(scope, id, props);
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic1', {
    displayName: 'Customer subscription topic'
  });
  
  // No policy statement requiring SSL
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic2');
  
  // Policy added but no SSL requirement
  topic.addToResourcePolicy(new iam.PolicyStatement({
    actions: ['sns:Publish'],
    principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:user/user1')],
    resources: [topic.topicArn]
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic3', {
    topicName: 'notifications-topic'
  });
  
  // Empty policy with no conditions
  const policyDocument = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        actions: ['sns:Publish'],
        principals: [new iam.AnyPrincipal()],
        resources: [topic.topicArn]
      })
    ]
  });
  
  const cfnTopic = topic.node.defaultChild as aws.CfnResource;
  cfnTopic.addPropertyOverride('TopicPolicy', policyDocument);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const myTopic = new sns.Topic(stack, 'MyTopic4');
  
  // Policy with wrong condition key
  myTopic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [myTopic.topicArn],
    conditions: {
      'StringEquals': {
        'aws:SourceAccount': '123456789012'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic5');
  
  // Policy with incorrect SecureTransport value (false)
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'false'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic6');
  
  // Multiple policies but none requiring SSL
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AccountPrincipal('123456789012')],
    actions: ['sns:Publish'],
    resources: [topic.topicArn]
  }));
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.DENY,
    principals: [new iam.AccountPrincipal('111111111111')],
    actions: ['sns:Publish'],
    resources: [topic.topicArn]
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic7');
  
  // Using CFN directly without SSL requirement
  const cfnTopic = topic.node.defaultChild as aws.CfnResource;
  cfnTopic.addPropertyOverride('TopicPolicy', {
    PolicyDocument: {
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sns:Publish',
          Resource: topic.topicArn
        }
      ]
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic8');
  
  // Using incorrect condition format
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'StringEquals': {
        'aws:SecureTransport': 'true' // Should be Bool, not StringEquals
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic9', {
    fifo: true,
    contentBasedDeduplication: true
  });
  
  // FIFO topic without SSL requirement
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic10');
  
  // Policy with incomplete condition
  const policyStatement = new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
    actions: ['sns:Publish'],
    resources: [topic.topicArn]
  });
  
  // Condition added but not for SecureTransport
  policyStatement.addCondition('StringEquals', {
    'aws:SourceAccount': stack.account
  });
  
  topic.addToResourcePolicy(policyStatement);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic11');
  
  // Using raw override without SSL requirement
  const cfnTopic = topic.node.defaultChild as aws.CfnResource;
  cfnTopic.addOverride('Properties.Policy', {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: 'sns:Publish',
        Resource: topic.topicArn
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  // Creating topic with encryption but no SSL policy
  const topic = new sns.Topic(stack, 'MyTopic12', {
    masterKey: new aws.aws_kms.Key(stack, 'TopicKey', {
      enableKeyRotation: true
    })
  });
  
  // Even with encryption, we need to explicitly set SSL requirement
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic13');
  
  // Policy with condition for a different action
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Subscribe'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
  
  // Missing condition for Publish action
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn]
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  const topic = new sns.Topic(stack, 'MyTopic14');
  
  // Creating a topic with subscription but no SSL policy
  topic.addSubscription(new aws.aws_sns_subscriptions.LambdaSubscription(
    new aws.aws_lambda.Function(stack, 'MyFunction', {
      runtime: aws.aws_lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: aws.aws_lambda.Code.fromInline(`
        exports.handler = async (event) => {
          console.log('Event:', JSON.stringify(event, null, 2));
          return { statusCode: 200, body: 'Success' };
        };
      `)
    })
  ));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(stack: aws.Stack) {
  // ruleid: typescript-cdk-sns-topic-ssl-publish-only
  // Using L1 construct directly without SSL requirement
  new aws.aws_sns.CfnTopic(stack, 'MyCfnTopic', {
    displayName: 'My CFN Topic',
    topicName: 'my-cfn-topic'
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(stack: aws.Stack) {
  const topic = new sns.Topic(stack, 'MySecureTopic1');
  
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2(stack: aws.Stack) {
  const topic = new sns.Topic(stack, 'MySecureTopic2');
  
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Using server-side encryption automatically enforces SSL
  new sns.TopicPolicy(stack, 'TopicPolicy', {
    topics: [topic],
    policyDocument: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          principals: [new iam.AnyPrincipal()],
          actions: ['sns:Publish'],
          resources: [topic.topicArn],
          conditions: {
            'Bool': {
              'aws:SecureTransport': 'true'
            }
          }
        })
      ]
    })
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Creating topic with server-side encryption enabled
  const encryptedTopic = new sns.Topic(stack, 'MySecureTopic3', {
    masterKey: new aws.aws_kms.Key(stack, 'TopicKey3', {
      enableKeyRotation: true
    }),
    enforcement: sns.TopicEncryption.ENFORCED // Explicitly enforce encryption
  });
  
  // With SSE enabled, SSL is automatically enforced
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4(stack: aws.Stack) {
  const topic = new sns.Topic(stack, 'MySecureTopic4');
  
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Multiple statements with SSL requirement
  const policy = new sns.TopicPolicy(stack, 'TopicPolicy4', {
    topics: [topic]
  });
  
  policy.document.addStatements(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
      actions: ['sns:Publish'],
      resources: [topic.topicArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': 'true'
        }
      }
    }),
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal('123456789012')],
      actions: ['sns:Subscribe'],
      resources: [topic.topicArn]
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(stack: aws.Stack) {
  const topic = new sns.Topic(stack, 'MySecureTopic5');
  
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Using CFN directly with SSL requirement
  const cfnTopic = topic.node.defaultChild as aws.CfnResource;
  cfnTopic.addPropertyOverride('TopicPolicy', {
    PolicyDocument: {
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sns:Publish',
          Resource: topic.topicArn,
          Condition: {
            Bool: {
              'aws:SecureTransport': 'true'
            }
          }
        }
      ]
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // FIFO topic with SSL requirement
  const topic = new sns.Topic(stack, 'MySecureTopic6', {
    fifo: true,
    contentBasedDeduplication: true
  });
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7(stack: aws.Stack) {
  const topic = new sns.Topic(stack, 'MySecureTopic7');
  
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Policy with multiple conditions including SSL
  const policyStatement = new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
    actions: ['sns:Publish'],
    resources: [topic.topicArn]
  });
  
  policyStatement.addCondition('StringEquals', {
    'aws:SourceAccount': stack.account
  });
  
  policyStatement.addCondition('Bool', {
    'aws:SecureTransport': 'true'
  });
  
  topic.addToResourcePolicy(policyStatement);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Using L1 construct with SSL requirement
  const cfnTopic = new aws.aws_sns.CfnTopic(stack, 'MySecureCfnTopic', {
    displayName: 'My Secure CFN Topic',
    topicName: 'my-secure-cfn-topic'
  });
  
  new aws.aws_sns.CfnTopicPolicy(stack, 'MyCfnTopicPolicy', {
    policyDocument: {
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sns:Publish',
          Resource: cfnTopic.ref,
          Condition: {
            Bool: {
              'aws:SecureTransport': 'true'
            }
          }
        }
      ]
    },
    topics: [cfnTopic.ref]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9(stack: aws.Stack) {
  const topic = new sns.Topic(stack, 'MySecureTopic9');
  
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Creating a topic with subscription and SSL policy
  topic.addSubscription(new aws.aws_sns_subscriptions.LambdaSubscription(
    new aws.aws_lambda.Function(stack, 'MySecureFunction', {
      runtime: aws.aws_lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: aws.aws_lambda.Code.fromInline(`
        exports.handler = async (event) => {
          console.log('Event:', JSON.stringify(event, null, 2));
          return { statusCode: 200, body: 'Success' };
        };
      `)
    })
  ));
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Topic with both encryption and explicit SSL policy
  const topic = new sns.Topic(stack, 'MySecureTopic10', {
    masterKey: new aws.aws_kms.Key(stack, 'TopicKey10', {
      enableKeyRotation: true
    })
  });
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Topic with SSL requirement for multiple actions
  const topic = new sns.Topic(stack, 'MySecureTopic11');
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish', 'sns:Subscribe'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Topic with deny policy for non-SSL and allow for SSL
  const topic = new sns.Topic(stack, 'MySecureTopic12');
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.DENY,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'false'
      }
    }
  }));
  
  topic.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    principals: [new iam.AnyPrincipal()],
    actions: ['sns:Publish'],
    resources: [topic.topicArn],
    conditions: {
      'Bool': {
        'aws:SecureTransport': 'true'
      }
    }
  }));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Topic with complex policy document
  const topic = new sns.Topic(stack, 'MySecureTopic13');
  
  const policyDocument = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
        actions: ['sns:Publish'],
        resources: [topic.topicArn],
        conditions: {
          'Bool': {
            'aws:SecureTransport': 'true'
          }
        }
      }),
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.AccountPrincipal(stack.account)],
        actions: ['sns:Subscribe'],
        resources: [topic.topicArn]
      })
    ]
  });
  
  new sns.TopicPolicy(stack, 'TopicPolicy13', {
    topics: [topic],
    policyDocument: policyDocument
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Using raw override with SSL requirement
  const topic = new sns.Topic(stack, 'MySecureTopic14');
  
  const cfnTopic = topic.node.defaultChild as aws.CfnResource;
  cfnTopic.addOverride('Properties.Policy', {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: 'sns:Publish',
        Resource: topic.topicArn,
        Condition: {
          Bool: {
            'aws:SecureTransport': 'true'
          }
        }
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(stack: aws.Stack) {
  // ok: typescript-cdk-sns-topic-ssl-publish-only
  // Using both KMS encryption and SSL policy
  const key = new aws.aws_kms.Key(stack, 'TopicKey15', {
    enableKeyRotation: true,
    description: 'KMS key for SNS topic encryption'
  });
  
  const topic = new sns.Topic(stack, 'MySecureTopic15', {
    masterKey: key,
    topicName: 'secure-topic-with-encryption'
  });
  
  // Even though SSE is enabled (which enforces SSL), we're explicitly adding the policy too
  const topicPolicy = new sns.TopicPolicy(stack, 'TopicPolicy15', {
    topics: [topic]
  });
  
  topicPolicy.document.addStatements(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      actions: ['sns:Publish'],
      resources: [topic.topicArn],
      conditions: {
        'Bool': {
          'aws:SecureTransport': 'true'
        }
      }
    })
  );
}
// {/fact}