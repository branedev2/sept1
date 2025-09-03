import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';

class SecurityTestStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
  }

  // True positives (vulnerable code)

  bad_case_1() {
    // ruleid: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MyProject1', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['echo "Hello, World!"'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      // No encryption key specified
    });
  }

  bad_case_2() {
    // ruleid: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MyProject2', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['npm test'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: undefined, // Explicitly undefined encryption key
    });
  }

  bad_case_3() {
    const buildSpec = codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        build: {
          commands: ['gradle build'],
        },
      },
    });
    
    // ruleid: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MyProject3', {
      buildSpec: buildSpec,
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      // Missing encryption key
    });
  }

  bad_case_4() {
    const projectProps: codebuild.ProjectProps = {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['mvn package'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      // No encryption key in props
    };
    
    // ruleid: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MyProject4', projectProps);
  }

  bad_case_5() {
    let encryptionKey = null;
    
    // ruleid: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MyProject5', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['echo "Building..."'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: encryptionKey, // Null encryption key
    });
  }

  bad_case_6() {
    const shouldUseEncryption = false;
    
    // ruleid: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MyProject6', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['yarn build'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: shouldUseEncryption ? new kms.Key(this, 'Key6') : undefined,
    });
  }

  bad_case_7() {
    const projectConfig = {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['make build'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
    };
    
    // ruleid: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MyProject7', projectConfig);
  }

  bad_case_8() {
    function createProject(id: string) {
      // ruleid: typescript_cdk_kmskey_encryption
      return new codebuild.Project(this, id, {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: '0.2',
          phases: {
            build: {
              commands: ['python setup.py build'],
            },
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        // Missing encryption key
      });
    }
    
    const project = createProject('MyProject8');
  }

  bad_case_9() {
    const environments = ['dev', 'staging', 'prod'];
    
    environments.forEach((env, index) => {
      // ruleid: typescript_cdk_kmskey_encryption
      new codebuild.Project(this, `MyProject9-${env}`, {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: '0.2',
          phases: {
            build: {
              commands: [`echo "Building for ${env}"`],
            },
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        // No encryption key
      });
    });
  }

  bad_case_10() {
    // ruleid: typescript_cdk_kmskey_encryption
    const project = new codebuild.PipelineProject(this, 'MyPipelineProject10', {
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      // Missing encryption key for pipeline project
    });
  }

  bad_case_11() {
    const buildEnvironment = {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    };
    
    // ruleid: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MyProject11', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['npm run build'],
          },
        },
      }),
      environment: buildEnvironment,
      // No encryption key
    });
  }

  bad_case_12() {
    // Creating multiple projects without encryption keys
    for (let i = 0; i < 3; i++) {
      // ruleid: typescript_cdk_kmskey_encryption
      new codebuild.Project(this, `MyProject12-${i}`, {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: '0.2',
          phases: {
            build: {
              commands: [`echo "Building instance ${i}"`],
            },
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        // No encryption key
      });
    }
  }

  bad_case_13() {
    const getEncryptionKey = () => {
      return undefined; // Returns undefined encryption key
    };
    
    // ruleid: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MyProject13', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['cargo build'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: getEncryptionKey(),
    });
  }

  bad_case_14() {
    const options = {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      computeType: codebuild.ComputeType.SMALL,
    };
    
    // ruleid: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MyProject14', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['dotnet build'],
          },
        },
      }),
      environment: options,
      // Missing encryption key
    });
  }

  bad_case_15() {
    // ruleid: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MyProject15', {
      buildSpec: codebuild.BuildSpec.fromSourceFilename('buildspec.yml'),
      source: codebuild.Source.gitHub({
        owner: 'myorg',
        repo: 'myrepo',
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      // No encryption key with GitHub source
    });
  }

  // True negatives (secure code)

  good_case_1() {
    const key = new kms.Key(this, 'Key1', {
      enableKeyRotation: true,
    });
    
    // ok: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MySecureProject1', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['echo "Hello, World!"'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Using a KMS key for encryption
    });
  }

  good_case_2() {
    // ok: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MySecureProject2', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['npm test'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: new kms.Key(this, 'Key2'), // Inline KMS key creation
    });
  }

  good_case_3() {
    const buildSpec = codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        build: {
          commands: ['gradle build'],
        },
      },
    });
    
    const key = new kms.Key(this, 'Key3', {
      description: 'Key for CodeBuild project',
      enableKeyRotation: true,
    });
    
    // ok: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MySecureProject3', {
      buildSpec: buildSpec,
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Using a configured KMS key
    });
  }

  good_case_4() {
    const key = kms.Key.fromKeyArn(this, 'ImportedKey4', 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab');
    
    const projectProps: codebuild.ProjectProps = {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['mvn package'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Using an imported KMS key
    };
    
    // ok: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MySecureProject4', projectProps);
  }

  good_case_5() {
    const key = new kms.Key(this, 'Key5', {
      alias: 'codebuild/project5',
      enableKeyRotation: true,
    });
    
    // ok: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MySecureProject5', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['echo "Building..."'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Using a KMS key with alias
    });
  }

  good_case_6() {
    const shouldUseEncryption = true;
    const key = new kms.Key(this, 'Key6', {
      enableKeyRotation: true,
    });
    
    // ok: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MySecureProject6', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['yarn build'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: shouldUseEncryption ? key : undefined, // Conditionally using a KMS key
    });
  }

  good_case_7() {
    const key = new kms.Key(this, 'Key7');
    
    const projectConfig = {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['make build'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Including KMS key in config object
    };
    
    // ok: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MySecureProject7', projectConfig);
  }

  good_case_8() {
    const key = new kms.Key(this, 'Key8');
    
    function createProject(id: string, key: kms.IKey) {
      // ok: typescript_cdk_kmskey_encryption
      return new codebuild.Project(this, id, {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: '0.2',
          phases: {
            build: {
              commands: ['python setup.py build'],
            },
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        encryptionKey: key, // Passing KMS key to factory function
      });
    }
    
    const project = createProject('MySecureProject8', key);
  }

  good_case_9() {
    const environments = ['dev', 'staging', 'prod'];
    const key = new kms.Key(this, 'Key9', {
      enableKeyRotation: true,
    });
    
    environments.forEach((env, index) => {
      // ok: typescript_cdk_kmskey_encryption
      new codebuild.Project(this, `MySecureProject9-${env}`, {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: '0.2',
          phases: {
            build: {
              commands: [`echo "Building for ${env}"`],
            },
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        encryptionKey: key, // Using same KMS key for multiple projects
      });
    });
  }

  good_case_10() {
    const key = new kms.Key(this, 'Key10');
    
    // ok: typescript_cdk_kmskey_encryption
    const project = new codebuild.PipelineProject(this, 'MySecurePipelineProject10', {
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Using KMS key for pipeline project
    });
  }

  good_case_11() {
    const buildEnvironment = {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
    };
    
    const key = kms.Key.fromKeyArn(
      this, 
      'ImportedKey11', 
      'arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'
    );
    
    // ok: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MySecureProject11', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['npm run build'],
          },
        },
      }),
      environment: buildEnvironment,
      encryptionKey: key, // Using imported KMS key
    });
  }

  good_case_12() {
    // Creating multiple projects with encryption keys
    for (let i = 0; i < 3; i++) {
      const key = new kms.Key(this, `Key12-${i}`);
      
      // ok: typescript_cdk_kmskey_encryption
      new codebuild.Project(this, `MySecureProject12-${i}`, {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: '0.2',
          phases: {
            build: {
              commands: [`echo "Building instance ${i}"`],
            },
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        encryptionKey: key, // Each project gets its own KMS key
      });
    }
  }

  good_case_13() {
    const getEncryptionKey = () => {
      return new kms.Key(this, 'Key13'); // Returns a new KMS key
    };
    
    // ok: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MySecureProject13', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['cargo build'],
          },
        },
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: getEncryptionKey(), // Using function to get KMS key
    });
  }

  good_case_14() {
    const options = {
      buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      computeType: codebuild.ComputeType.SMALL,
    };
    
    const key = new kms.Key(this, 'Key14', {
      description: 'KMS key for CodeBuild artifacts',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    
    // ok: typescript_cdk_kmskey_encryption
    new codebuild.Project(this, 'MySecureProject14', {
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          build: {
            commands: ['dotnet build'],
          },
        },
      }),
      environment: options,
      encryptionKey: key, // Using a fully configured KMS key
    });
  }

  good_case_15() {
    const key = new kms.Key(this, 'Key15');
    
    // Add permissions to the key for the project
    key.addToResourcePolicy(new iam.PolicyStatement({
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:DescribeKey'],
      resources: ['*'],
      principals: [new iam.ServicePrincipal('codebuild.amazonaws.com')],
    }));
    
    // ok: typescript_cdk_kmskey_encryption
    const project = new codebuild.Project(this, 'MySecureProject15', {
      buildSpec: codebuild.BuildSpec.fromSourceFilename('buildspec.yml'),
      source: codebuild.Source.gitHub({
        owner: 'myorg',
        repo: 'myrepo',
      }),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
      },
      encryptionKey: key, // Using KMS key with GitHub source and explicit permissions
    });
  }
}