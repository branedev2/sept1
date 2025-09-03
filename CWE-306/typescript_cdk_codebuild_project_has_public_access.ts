import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';

// True Positives (Vulnerable Cases)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Basic case with badge enabled
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject1', {
    buildSpec: codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        build: {
          commands: ['npm test']
        }
      }
    }),
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: true, // This makes build results publicly accessible
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // With source configuration but still has public badge
  const source = codebuild.Source.gitHub({
    owner: 'myorg',
    repo: 'myrepo',
    webhook: true,
  });
  
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject2', {
    source,
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // With explicit true value in a variable
  const enableBadge = true;
  
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject3', {
    buildSpec: codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        build: {
          commands: ['echo "Building..."']
        }
      }
    }),
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: enableBadge,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // With conditional that always evaluates to true
  const isPublic = process.env.NODE_ENV === 'development' || true;
  
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject4', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: isPublic,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // With artifacts configuration but still has public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject5', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    artifacts: codebuild.Artifacts.s3({
      bucket: new s3.Bucket(scope, 'ArtifactBucket'),
      includeBuildId: true,
      packageZip: true,
    }),
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // With environment variables containing sensitive data
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject6', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      environmentVariables: {
        API_KEY: { value: 'secret-api-key' },
        DATABASE_URL: { value: 'mysql://user:password@localhost/db' }
      }
    },
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // With privileged mode enabled and public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject7', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      privileged: true,
    },
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // With role with elevated permissions and public badge
  const role = new iam.Role(scope, 'CodeBuildRole', {
    assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com'),
  });
  role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess'));
  
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject8', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    role,
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // With VPC configuration but still has public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  const project = new codebuild.PipelineProject(scope, 'MyProject9', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // With timeout configuration but still has public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject10', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    timeout: cdk.Duration.hours(1),
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // With encryption key but still has public badge
  const encryptionKey = new cdk.aws_kms.Key(scope, 'EncryptionKey');
  
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject11', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    encryptionKey,
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // With cache configuration but still has public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject12', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    cache: codebuild.Cache.local(codebuild.LocalCacheMode.DOCKER_LAYER),
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct, projectName: string) {
  // With dynamic project name but still has public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject13', {
    projectName,
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // With file system location but still has public badge
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject14', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    fileSystemLocations: [
      codebuild.FileSystemLocation.efs({
        identifier: 'myefs',
        location: 'fs-12345678:/directory',
        mountPoint: '/mnt/efs',
        mountOptions: 'rw,tls',
      }),
    ],
    badge: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // With secondary sources but still has public badge
  const mainSource = codebuild.Source.gitHub({
    owner: 'myorg',
    repo: 'main-repo',
  });
  
  const secondarySource = codebuild.Source.gitHub({
    owner: 'myorg',
    repo: 'secondary-repo',
    identifier: 'SecondarySource',
  });
  
  // ruleid: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject15', {
    source: mainSource,
    secondarySources: [secondarySource],
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: true,
  });
}
// {/fact}

// True Negatives (Safe Cases)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Basic case with badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject1', {
    buildSpec: codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        build: {
          commands: ['npm test']
        }
      }
    }),
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // With source configuration and badge disabled
  const source = codebuild.Source.gitHub({
    owner: 'myorg',
    repo: 'myrepo',
    webhook: true,
  });
  
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject2', {
    source,
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // With explicit false value in a variable
  const enableBadge = false;
  
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject3', {
    buildSpec: codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        build: {
          commands: ['echo "Building..."']
        }
      }
    }),
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: enableBadge,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // With badge property omitted (defaults to false)
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject4', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    // No badge property means it defaults to false
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // With artifacts configuration and badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject5', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    artifacts: codebuild.Artifacts.s3({
      bucket: new s3.Bucket(scope, 'ArtifactBucket'),
      includeBuildId: true,
      packageZip: true,
    }),
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // With environment variables containing sensitive data but badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject6', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      environmentVariables: {
        API_KEY: { 
          value: secretsmanager.Secret.fromSecretNameV2(scope, 'ApiKeySecret', 'api-key').secretValue.toString()
        },
        DATABASE_URL: { 
          value: secretsmanager.Secret.fromSecretNameV2(scope, 'DbUrlSecret', 'db-url').secretValue.toString()
        }
      }
    },
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // With privileged mode enabled but badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject7', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      privileged: true,
    },
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // With role with elevated permissions but badge disabled
  const role = new iam.Role(scope, 'CodeBuildRole', {
    assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com'),
  });
  role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3ReadOnlyAccess'));
  
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject8', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    role,
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // With VPC configuration and badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  const project = new codebuild.PipelineProject(scope, 'MyProject9', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // With timeout configuration and badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject10', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    timeout: cdk.Duration.hours(1),
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // With encryption key and badge disabled
  const encryptionKey = new cdk.aws_kms.Key(scope, 'EncryptionKey');
  
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject11', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    encryptionKey,
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // With cache configuration and badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject12', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    cache: codebuild.Cache.local(codebuild.LocalCacheMode.DOCKER_LAYER),
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using parameter store to determine badge value (set to false)
  const badgeParam = ssm.StringParameter.valueForStringParameter(scope, '/myapp/codebuild/badge');
  const enableBadge = badgeParam === 'true';
  
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject13', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: false, // Explicitly set to false regardless of parameter
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // With file system location and badge disabled
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject14', {
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    fileSystemLocations: [
      codebuild.FileSystemLocation.efs({
        identifier: 'myefs',
        location: 'fs-12345678:/directory',
        mountPoint: '/mnt/efs',
        mountOptions: 'rw,tls',
      }),
    ],
    badge: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // With secondary sources and badge disabled
  const mainSource = codebuild.Source.gitHub({
    owner: 'myorg',
    repo: 'main-repo',
  });
  
  const secondarySource = codebuild.Source.gitHub({
    owner: 'myorg',
    repo: 'secondary-repo',
    identifier: 'SecondarySource',
  });
  
  // ok: typescript_cdk_codebuild_project_has_public_access
  new codebuild.Project(scope, 'MyProject15', {
    source: mainSource,
    secondarySources: [secondarySource],
    environment: {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    },
    badge: false,
  });
}
// {/fact}