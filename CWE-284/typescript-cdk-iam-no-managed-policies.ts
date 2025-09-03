import { Stack, StackProps, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Role, User, Group, ManagedPolicy, PolicyStatement, PolicyDocument, Effect } from 'aws-cdk-lib/aws-iam';

// TRUE POSITIVES (Vulnerable Code Examples)

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_1() {
  const stack = new Stack();
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'MyRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    managedPolicies: [
      ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess')
    ]
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_2() {
  const stack = new Stack();
  const user = new User(stack, 'AdminUser');
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  user.addManagedPolicy(
    ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess')
  );
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_3() {
  const stack = new Stack();
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const group = new Group(stack, 'DevelopersGroup', {
    managedPolicies: [
      ManagedPolicy.fromAwsManagedPolicyName('AmazonDynamoDBFullAccess'),
      ManagedPolicy.fromAwsManagedPolicyName('AmazonSQSFullAccess')
    ]
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_4() {
  const stack = new Stack();
  const role = new Role(stack, 'LambdaRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com')
  });
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  role.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AWSLambdaBasicExecutionRole'));
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_5() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript-cdk-iam-no-managed-policies
      new Role(this, 'MyRole', {
        assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
        managedPolicies: [
          ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2FullAccess')
        ]
      });
    }
  }
  
  const stack = new Stack();
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_6() {
  const stack = new Stack();
  const user = new User(stack, 'DataScientist');
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  for (const policyName of ['AmazonS3ReadOnlyAccess', 'AmazonAthenaFullAccess']) {
    user.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName));
  }
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_7() {
  const stack = new Stack();
  
  const policies = {
    s3: 'AmazonS3FullAccess',
    dynamo: 'AmazonDynamoDBFullAccess'
  };
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'DataProcessingRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    managedPolicies: [
      ManagedPolicy.fromAwsManagedPolicyName(policies.s3),
      ManagedPolicy.fromAwsManagedPolicyName(policies.dynamo)
    ]
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_8() {
  const stack = new Stack();
  const group = new Group(stack, 'NetworkAdmins');
  
  if (process.env.ENVIRONMENT === 'production') {
    // ruleid: typescript-cdk-iam-no-managed-policies
    group.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonVPCFullAccess'));
  } else {
    // ruleid: typescript-cdk-iam-no-managed-policies
    group.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonVPCReadOnlyAccess'));
  }
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_9() {
  class SecurityStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript-cdk-iam-no-managed-policies
      const securityRole = new Role(this, 'SecurityAuditRole', {
        assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
        managedPolicies: [
          ManagedPolicy.fromAwsManagedPolicyName('SecurityAudit')
        ]
      });
    }
  }
  
  const app = new App();
  new SecurityStack(app, 'SecurityStack');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_10() {
  const stack = new Stack();
  
  function createUserWithAccess(userName: string, policyName: string) {
    const user = new User(stack, userName);
    // ruleid: typescript-cdk-iam-no-managed-policies
    user.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName));
    return user;
  }
  
  createUserWithAccess('DatabaseAdmin', 'AmazonRDSFullAccess');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_11() {
  const stack = new Stack();
  const awsManagedPolicies = [
    'AmazonEKSClusterPolicy',
    'AmazonEKSServicePolicy'
  ];
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'EKSRole', {
    assumedBy: new ServicePrincipal('eks.amazonaws.com'),
    managedPolicies: awsManagedPolicies.map(policyName => 
      ManagedPolicy.fromAwsManagedPolicyName(policyName)
    )
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_12() {
  const stack = new Stack();
  
  const policyMapping = new Map<string, string>([
    ['backup', 'AWSBackupOperatorAccess'],
    ['monitoring', 'CloudWatchFullAccess']
  ]);
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'MonitoringRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    managedPolicies: [
      ManagedPolicy.fromAwsManagedPolicyName(policyMapping.get('monitoring')!)
    ]
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_13() {
  const stack = new Stack();
  
  class UserWithPolicy {
    constructor(scope: Construct, userName: string, policyName: string) {
      const user = new User(scope, userName);
      // ruleid: typescript-cdk-iam-no-managed-policies
      user.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName));
    }
  }
  
  new UserWithPolicy(stack, 'CloudFormationUser', 'AWSCloudFormationFullAccess');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_14() {
  const stack = new Stack();
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'CodeBuildRole', {
    assumedBy: new ServicePrincipal('codebuild.amazonaws.com'),
    managedPolicies: [
      ManagedPolicy.fromAwsManagedPolicyName('AWSCodeBuildAdminAccess')
    ],
    description: 'Role for CodeBuild projects'
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_15() {
  const stack = new Stack();
  
  const getRequiredPolicies = () => {
    return [
      'AmazonECR-FullAccess',
      'AmazonECS-FullAccess'
    ];
  };
  
  // ruleid: typescript-cdk-iam-no-managed-policies
  const containerRole = new Role(stack, 'ContainerRole', {
    assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com'),
    managedPolicies: getRequiredPolicies().map(policy => 
      ManagedPolicy.fromAwsManagedPolicyName(policy)
    )
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_1() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'MyRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    inlinePolicies: {
      's3Access': new PolicyDocument({
        statements: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['s3:GetObject', 's3:PutObject'],
            resources: ['arn:aws:s3:::my-bucket/*']
          })
        ]
      })
    }
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_2() {
  const stack = new Stack();
  const user = new User(stack, 'AdminUser');
  
  // ok: typescript-cdk-iam-no-managed-policies
  user.attachInlinePolicy(new Policy(stack, 'AdminUserPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:ListAllMyBuckets'],
        resources: ['*']
      })
    ]
  }));
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_3() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const group = new Group(stack, 'DevelopersGroup');
  
  const customPolicy = new ManagedPolicy(stack, 'DevelopersPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:PutItem'],
        resources: ['arn:aws:dynamodb:*:*:table/my-table']
      }),
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sqs:SendMessage', 'sqs:ReceiveMessage'],
        resources: ['arn:aws:sqs:*:*:my-queue']
      })
    ]
  });
  
  group.addManagedPolicy(customPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_4() {
  const stack = new Stack();
  const role = new Role(stack, 'LambdaRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com')
  });
  
  // ok: typescript-cdk-iam-no-managed-policies
  role.addToPolicy(new PolicyStatement({
    effect: Effect.ALLOW,
    actions: [
      'logs:CreateLogGroup',
      'logs:CreateLogStream',
      'logs:PutLogEvents'
    ],
    resources: ['arn:aws:logs:*:*:*']
  }));
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_5() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript-cdk-iam-no-managed-policies
      const role = new Role(this, 'MyRole', {
        assumedBy: new ServicePrincipal('ec2.amazonaws.com')
      });
      
      role.addToPolicy(new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'ec2:DescribeInstances',
          'ec2:StartInstances',
          'ec2:StopInstances'
        ],
        resources: ['*']
      }));
    }
  }
  
  const stack = new Stack();
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_6() {
  const stack = new Stack();
  const user = new User(stack, 'DataScientist');
  
  // ok: typescript-cdk-iam-no-managed-policies
  const customPolicy = new ManagedPolicy(stack, 'DataScientistPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:GetObject', 's3:ListBucket'],
        resources: [
          'arn:aws:s3:::data-bucket',
          'arn:aws:s3:::data-bucket/*'
        ]
      }),
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['athena:StartQueryExecution', 'athena:GetQueryResults'],
        resources: ['*']
      })
    ]
  });
  
  user.addManagedPolicy(customPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_7() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const role = new Role(stack, 'DataProcessingRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    inlinePolicies: {
      's3Access': new PolicyDocument({
        statements: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['s3:*'],
            resources: ['arn:aws:s3:::data-processing-bucket/*']
          })
        ]
      }),
      'dynamoAccess': new PolicyDocument({
        statements: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['dynamodb:*'],
            resources: ['arn:aws:dynamodb:*:*:table/data-table']
          })
        ]
      })
    }
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_8() {
  const stack = new Stack();
  const group = new Group(stack, 'NetworkAdmins');
  
  // ok: typescript-cdk-iam-no-managed-policies
  const policyDocument = new PolicyDocument({
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: process.env.ENVIRONMENT === 'production' 
          ? ['vpc:*'] 
          : ['vpc:Describe*'],
        resources: ['*']
      })
    ]
  });
  
  group.attachInlinePolicy(new Policy(stack, 'NetworkPolicy', {
    document: policyDocument
  }));
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_9() {
  class SecurityStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ok: typescript-cdk-iam-no-managed-policies
      const securityPolicy = new ManagedPolicy(this, 'SecurityAuditPolicy', {
        statements: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: [
              'cloudtrail:LookupEvents',
              'cloudtrail:DescribeTrails',
              'cloudwatch:DescribeAlarms',
              'config:DescribeConfigRules'
            ],
            resources: ['*']
          })
        ]
      });
      
      const securityRole = new Role(this, 'SecurityAuditRole', {
        assumedBy: new ServicePrincipal('lambda.amazonaws.com')
      });
      
      securityRole.addManagedPolicy(securityPolicy);
    }
  }
  
  const app = new App();
  new SecurityStack(app, 'SecurityStack');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_10() {
  const stack = new Stack();
  
  function createUserWithAccess(userName: string) {
    const user = new User(stack, userName);
    
    // ok: typescript-cdk-iam-no-managed-policies
    user.attachInlinePolicy(new Policy(stack, `${userName}Policy`, {
      statements: [
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: [
            'rds:DescribeDBInstances',
            'rds:ModifyDBInstance'
          ],
          resources: ['arn:aws:rds:*:*:db:*']
        })
      ]
    }));
    
    return user;
  }
  
  createUserWithAccess('DatabaseAdmin');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_11() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const eksPolicy = new ManagedPolicy(stack, 'EKSCustomPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'eks:CreateCluster',
          'eks:DeleteCluster',
          'eks:DescribeCluster'
        ],
        resources: ['*']
      }),
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'iam:PassRole'
        ],
        resources: ['arn:aws:iam::*:role/eks-*']
      })
    ]
  });
  
  const role = new Role(stack, 'EKSRole', {
    assumedBy: new ServicePrincipal('eks.amazonaws.com')
  });
  
  role.addManagedPolicy(eksPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_12() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const monitoringPolicy = new ManagedPolicy(stack, 'MonitoringPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'cloudwatch:PutMetricData',
          'cloudwatch:GetMetricData',
          'cloudwatch:DescribeAlarms'
        ],
        resources: ['*']
      }),
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'logs:CreateLogGroup',
          'logs:CreateLogStream',
          'logs:PutLogEvents'
        ],
        resources: ['arn:aws:logs:*:*:*']
      })
    ]
  });
  
  const role = new Role(stack, 'MonitoringRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com')
  });
  
  role.addManagedPolicy(monitoringPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_13() {
  const stack = new Stack();
  
  class UserWithPolicy {
    constructor(scope: Construct, userName: string) {
      const user = new User(scope, userName);
      
      // ok: typescript-cdk-iam-no-managed-policies
      const cfnPolicy = new ManagedPolicy(scope, `${userName}Policy`, {
        statements: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: [
              'cloudformation:DescribeStacks',
              'cloudformation:CreateStack',
              'cloudformation:UpdateStack'
            ],
            resources: ['arn:aws:cloudformation:*:*:stack/*']
          })
        ]
      });
      
      user.addManagedPolicy(cfnPolicy);
    }
  }
  
  new UserWithPolicy(stack, 'CloudFormationUser');
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_14() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const codeBuildPolicy = new ManagedPolicy(stack, 'CodeBuildCustomPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'codebuild:CreateProject',
          'codebuild:StartBuild',
          'codebuild:BatchGetBuilds'
        ],
        resources: ['*']
      }),
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'logs:CreateLogGroup',
          'logs:CreateLogStream',
          'logs:PutLogEvents'
        ],
        resources: ['arn:aws:logs:*:*:*']
      })
    ]
  });
  
  const role = new Role(stack, 'CodeBuildRole', {
    assumedBy: new ServicePrincipal('codebuild.amazonaws.com'),
    description: 'Role for CodeBuild projects'
  });
  
  role.addManagedPolicy(codeBuildPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_15() {
  const stack = new Stack();
  
  // ok: typescript-cdk-iam-no-managed-policies
  const containerPolicy = new ManagedPolicy(stack, 'ContainerServicesPolicy', {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'ecr:GetDownloadUrlForLayer',
          'ecr:BatchGetImage',
          'ecr:BatchCheckLayerAvailability',
          'ecr:PutImage',
          'ecr:InitiateLayerUpload',
          'ecr:UploadLayerPart',
          'ecr:CompleteLayerUpload'
        ],
        resources: ['arn:aws:ecr:*:*:repository/*']
      }),
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'ecs:CreateService',
          'ecs:UpdateService',
          'ecs:RegisterTaskDefinition'
        ],
        resources: ['*']
      })
    ]
  });
  
  const containerRole = new Role(stack, 'ContainerRole', {
    assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com')
  });
  
  containerRole.addManagedPolicy(containerPolicy);
}
// {/fact}