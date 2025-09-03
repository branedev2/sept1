import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';

class EcrRepositoryStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }

  // True Positive Examples (Vulnerable Code)

  public bad_case_1() {
    // Creating an ECR repository with wildcard principal in policy
    const repository = new ecr.Repository(this, 'MyRepository1', {
      repositoryName: 'my-repository-1',
    });

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      actions: ['ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage'],
    }));
  }

  public bad_case_2() {
    // Creating an ECR repository with wildcard principal in policy using string
    const repository = new ecr.Repository(this, 'MyRepository2', {
      repositoryName: 'my-repository-2',
    });

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.StarPrincipal()],
      actions: ['ecr:PutImage', 'ecr:InitiateLayerUpload'],
    }));
  }

  public bad_case_3() {
    // Creating an ECR repository with wildcard principal in policy using multiple statements
    const repository = new ecr.Repository(this, 'MyRepository3', {
      repositoryName: 'my-repository-3',
    });

    const policyStatement = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ecr:GetAuthorizationToken'],
    });
    policyStatement.addPrincipals(new iam.AnyPrincipal());
    
    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(policyStatement);
  }

  public bad_case_4() {
    // Creating an ECR repository with wildcard principal in policy using variable
    const repository = new ecr.Repository(this, 'MyRepository4', {
      repositoryName: 'my-repository-4',
    });

    const anyPrincipal = new iam.AnyPrincipal();
    
    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [anyPrincipal],
      actions: ['ecr:BatchCheckLayerAvailability', 'ecr:GetRepositoryPolicy'],
    }));
  }

  public bad_case_5() {
    // Creating an ECR repository with wildcard principal in policy with condition
    const repository = new ecr.Repository(this, 'MyRepository5', {
      repositoryName: 'my-repository-5',
    });

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.StarPrincipal()],
      actions: ['ecr:DescribeImages'],
      conditions: {
        'StringEquals': {
          'aws:SourceVpc': 'vpc-12345678'
        }
      }
    }));
  }

  public bad_case_6() {
    // Creating an ECR repository with wildcard principal in policy with multiple principals
    const repository = new ecr.Repository(this, 'MyRepository6', {
      repositoryName: 'my-repository-6',
    });

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [
        new iam.ArnPrincipal('arn:aws:iam::123456789012:role/specific-role'),
        new iam.AnyPrincipal()
      ],
      actions: ['ecr:ListImages', 'ecr:BatchDeleteImage'],
    }));
  }

  public bad_case_7() {
    // Creating an ECR repository with wildcard principal in policy with resources
    const repository = new ecr.Repository(this, 'MyRepository7', {
      repositoryName: 'my-repository-7',
    });

    const policyStatement = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ecr:GetLifecyclePolicy', 'ecr:PutLifecyclePolicy'],
    });
    policyStatement.addPrincipals(new iam.StarPrincipal());
    policyStatement.addResources(repository.repositoryArn);
    
    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(policyStatement);
  }

  public bad_case_8() {
    // Creating an ECR repository with wildcard principal in policy with not actions
    const repository = new ecr.Repository(this, 'MyRepository8', {
      repositoryName: 'my-repository-8',
    });

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      notActions: ['ecr:DeleteRepository'],
    }));
  }

  public bad_case_9() {
    // Creating an ECR repository with wildcard principal in policy with deny effect
    const repository = new ecr.Repository(this, 'MyRepository9', {
      repositoryName: 'my-repository-9',
    });

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      principals: [new iam.StarPrincipal()],
      actions: ['ecr:DeleteRepositoryPolicy'],
    }));
  }

  public bad_case_10() {
    // Creating an ECR repository with multiple policy statements including wildcard
    const repository = new ecr.Repository(this, 'MyRepository10', {
      repositoryName: 'my-repository-10',
    });

    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:role/admin')],
      actions: ['ecr:*'],
    }));

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      actions: ['ecr:GetRepositoryPolicy'],
    }));
  }

  public bad_case_11() {
    // Creating an ECR repository with wildcard principal in policy using function
    const repository = new ecr.Repository(this, 'MyRepository11', {
      repositoryName: 'my-repository-11',
    });

    const getPrincipal = () => {
      return new iam.AnyPrincipal();
    };

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [getPrincipal()],
      actions: ['ecr:GetDownloadUrlForLayer'],
    }));
  }

  public bad_case_12() {
    // Creating an ECR repository with wildcard principal in policy with conditional logic
    const repository = new ecr.Repository(this, 'MyRepository12', {
      repositoryName: 'my-repository-12',
    });

    const isPublic = true;
    let principal;
    
    if (isPublic) {
      principal = new iam.StarPrincipal();
    } else {
      principal = new iam.ArnPrincipal('arn:aws:iam::123456789012:role/specific-role');
    }

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [principal],
      actions: ['ecr:BatchGetImage'],
    }));
  }

  public bad_case_13() {
    // Creating an ECR repository with wildcard principal in policy with array spread
    const repository = new ecr.Repository(this, 'MyRepository13', {
      repositoryName: 'my-repository-13',
    });

    const principals = [
      new iam.ArnPrincipal('arn:aws:iam::123456789012:role/role1'),
      new iam.AnyPrincipal()
    ];

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [...principals],
      actions: ['ecr:GetLifecyclePolicy'],
    }));
  }

  public bad_case_14() {
    // Creating an ECR repository with wildcard principal in policy with chained methods
    const repository = new ecr.Repository(this, 'MyRepository14', {
      repositoryName: 'my-repository-14',
    });

    const statement = new iam.PolicyStatement()
      .addActions('ecr:DescribeImages')
      .addPrincipals(new iam.StarPrincipal())
      .effect(iam.Effect.ALLOW);

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(statement);
  }

  public bad_case_15() {
    // Creating an ECR repository with wildcard principal in policy using a factory pattern
    const repository = new ecr.Repository(this, 'MyRepository15', {
      repositoryName: 'my-repository-15',
    });

    const createStatement = (action: string) => {
      return new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [action],
      });
    };

    // ruleid: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(createStatement('ecr:ListImages'));
  }

  // True Negative Examples (Secure Code)

  public good_case_1() {
    // Creating an ECR repository with specific IAM role principal
    const repository = new ecr.Repository(this, 'SecureRepository1', {
      repositoryName: 'secure-repository-1',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:role/specific-role')],
      actions: ['ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage'],
    }));
  }

  public good_case_2() {
    // Creating an ECR repository with specific IAM user principal
    const repository = new ecr.Repository(this, 'SecureRepository2', {
      repositoryName: 'secure-repository-2',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:user/specific-user')],
      actions: ['ecr:PutImage', 'ecr:InitiateLayerUpload'],
    }));
  }

  public good_case_3() {
    // Creating an ECR repository with AWS service principal
    const repository = new ecr.Repository(this, 'SecureRepository3', {
      repositoryName: 'secure-repository-3',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('codebuild.amazonaws.com')],
      actions: ['ecr:GetAuthorizationToken'],
    }));
  }

  public good_case_4() {
    // Creating an ECR repository with account principal
    const repository = new ecr.Repository(this, 'SecureRepository4', {
      repositoryName: 'secure-repository-4',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal('123456789012')],
      actions: ['ecr:BatchCheckLayerAvailability', 'ecr:GetRepositoryPolicy'],
    }));
  }

  public good_case_5() {
    // Creating an ECR repository with organization principal
    const repository = new ecr.Repository(this, 'SecureRepository5', {
      repositoryName: 'secure-repository-5',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.OrganizationPrincipal('o-exampleorgid')],
      actions: ['ecr:DescribeImages'],
    }));
  }

  public good_case_6() {
    // Creating an ECR repository with multiple specific principals
    const repository = new ecr.Repository(this, 'SecureRepository6', {
      repositoryName: 'secure-repository-6',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [
        new iam.ArnPrincipal('arn:aws:iam::123456789012:role/role1'),
        new iam.ArnPrincipal('arn:aws:iam::123456789012:role/role2')
      ],
      actions: ['ecr:ListImages', 'ecr:BatchDeleteImage'],
    }));
  }

  public good_case_7() {
    // Creating an ECR repository with federated principal
    const repository = new ecr.Repository(this, 'SecureRepository7', {
      repositoryName: 'secure-repository-7',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.FederatedPrincipal(
        'cognito-identity.amazonaws.com',
        {
          'StringEquals': {
            'cognito-identity.amazonaws.com:aud': 'us-east-1:12345678-abcd-1234-efgh-123456789012'
          }
        },
        'sts:AssumeRoleWithWebIdentity'
      )],
      actions: ['ecr:GetLifecyclePolicy', 'ecr:PutLifecyclePolicy'],
    }));
  }

  public good_case_8() {
    // Creating an ECR repository with canonical user principal
    const repository = new ecr.Repository(this, 'SecureRepository8', {
      repositoryName: 'secure-repository-8',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.CanonicalUserPrincipal('79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be')],
      actions: ['ecr:GetRepositoryPolicy'],
    }));
  }

  public good_case_9() {
    // Creating an ECR repository with specific principal using addPrincipals method
    const repository = new ecr.Repository(this, 'SecureRepository9', {
      repositoryName: 'secure-repository-9',
    });

    const policyStatement = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ecr:DeleteRepositoryPolicy'],
    });
    
    // ok: typescript_cdk_ecr_open_access
    policyStatement.addPrincipals(new iam.AccountPrincipal('123456789012'));
    repository.addToResourcePolicy(policyStatement);
  }

  public good_case_10() {
    // Creating an ECR repository with multiple policy statements, all with specific principals
    const repository = new ecr.Repository(this, 'SecureRepository10', {
      repositoryName: 'secure-repository-10',
    });

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:role/admin')],
      actions: ['ecr:*'],
    }));

    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
      actions: ['ecr:GetRepositoryPolicy'],
    }));
  }

  public good_case_11() {
    // Creating an ECR repository with specific principal using function
    const repository = new ecr.Repository(this, 'SecureRepository11', {
      repositoryName: 'secure-repository-11',
    });

    const getPrincipal = () => {
      return new iam.ArnPrincipal('arn:aws:iam::123456789012:role/specific-role');
    };

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [getPrincipal()],
      actions: ['ecr:GetDownloadUrlForLayer'],
    }));
  }

  public good_case_12() {
    // Creating an ECR repository with specific principal with conditional logic
    const repository = new ecr.Repository(this, 'SecureRepository12', {
      repositoryName: 'secure-repository-12',
    });

    const isPublic = false;
    let principal;
    
    if (isPublic) {
      principal = new iam.AccountPrincipal('123456789012');
    } else {
      principal = new iam.ArnPrincipal('arn:aws:iam::123456789012:role/specific-role');
    }

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [principal],
      actions: ['ecr:BatchGetImage'],
    }));
  }

  public good_case_13() {
    // Creating an ECR repository with specific principals with array spread
    const repository = new ecr.Repository(this, 'SecureRepository13', {
      repositoryName: 'secure-repository-13',
    });

    const principals = [
      new iam.ArnPrincipal('arn:aws:iam::123456789012:role/role1'),
      new iam.ArnPrincipal('arn:aws:iam::123456789012:role/role2')
    ];

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [...principals],
      actions: ['ecr:GetLifecyclePolicy'],
    }));
  }

  public good_case_14() {
    // Creating an ECR repository with specific principal with chained methods
    const repository = new ecr.Repository(this, 'SecureRepository14', {
      repositoryName: 'secure-repository-14',
    });

    // ok: typescript_cdk_ecr_open_access
    const statement = new iam.PolicyStatement()
      .addActions('ecr:DescribeImages')
      .addPrincipals(new iam.ServicePrincipal('ecs.amazonaws.com'))
      .effect(iam.Effect.ALLOW);

    repository.addToResourcePolicy(statement);
  }

  public good_case_15() {
    // Creating an ECR repository with specific principal using a factory pattern
    const repository = new ecr.Repository(this, 'SecureRepository15', {
      repositoryName: 'secure-repository-15',
    });

    const createStatement = (action: string) => {
      return new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.AccountPrincipal('123456789012')],
        actions: [action],
      });
    };

    // ok: typescript_cdk_ecr_open_access
    repository.addToResourcePolicy(createStatement('ecr:ListImages'));
  }
}

const app = new cdk.App();
new EcrRepositoryStack(app, 'EcrRepositoryStack');