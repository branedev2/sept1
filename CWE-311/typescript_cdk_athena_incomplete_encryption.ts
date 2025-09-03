import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating Athena WorkGroup without any encryption configuration
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupNoEncryption', {
    name: 'query-results-no-encryption',
    description: 'WorkGroup without encryption configuration',
    recursiveDeleteOption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating Athena WorkGroup with empty result configuration
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupEmptyResultConfig', {
    name: 'query-results-empty-config',
    workGroupConfiguration: {
      resultConfiguration: {},
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with output location but no encryption
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupOutputNoEncryption', {
    name: 'query-results-output-no-encryption',
    workGroupConfiguration: {
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with empty encryption configuration
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupEmptyEncryption', {
    name: 'query-results-empty-encryption',
    workGroupConfiguration: {
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {},
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption but not enforcing it
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupNoEnforcement', {
    name: 'query-results-no-enforcement',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: false,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating Athena WorkGroup with configuration but no result configuration
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupNoResultConfig', {
    name: 'query-results-no-result-config',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      bytesScannedCutoffPerQuery: 10000000,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating Athena WorkGroup with props object that doesn't include encryption
  const workGroupProps = {
    name: 'query-results-props-no-encryption',
    description: 'WorkGroup created from props object without encryption',
  };
  
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupPropsNoEncryption', workGroupProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with conditional encryption that might be skipped
  const includeEncryption = false;
  const workGroupConfig: any = {
    resultConfiguration: {
      outputLocation: `s3://${outputBucket.bucketName}/results/`,
    },
  };
  
  if (includeEncryption) {
    workGroupConfig.resultConfiguration.encryptionConfiguration = {
      encryptionOption: 'SSE_S3',
    };
  }
  
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupConditionalEncryption', {
    name: 'query-results-conditional-encryption',
    workGroupConfiguration: workGroupConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with undefined encryption option
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupUndefinedEncryption', {
    name: 'query-results-undefined-encryption',
    workGroupConfiguration: {
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: undefined,
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating multiple Athena WorkGroups in a loop without encryption
  const workGroupNames = ['analytics', 'reporting', 'dashboard'];
  
  for (const name of workGroupNames) {
    // ruleid: typescript_cdk_athena_incomplete_encryption
    new athena.CfnWorkGroup(scope, `AthenaWorkGroup${name}`, {
      name: `query-results-${name}`,
      description: `WorkGroup for ${name} without encryption`,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption configuration but missing encryptionOption
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupMissingEncryptionOption', {
    name: 'query-results-missing-encryption-option',
    workGroupConfiguration: {
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          // encryptionOption is missing
          kmsKey: 'some-key',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating Athena WorkGroup with configuration set to null
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupNullConfig', {
    name: 'query-results-null-config',
    workGroupConfiguration: null,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating Athena WorkGroup with empty string for encryption option
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupEmptyEncryptionOption', {
    name: 'query-results-empty-encryption-option',
    workGroupConfiguration: {
      resultConfiguration: {
        encryptionConfiguration: {
          encryptionOption: '',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating Athena WorkGroup with invalid encryption option
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupInvalidEncryptionOption', {
    name: 'query-results-invalid-encryption',
    workGroupConfiguration: {
      resultConfiguration: {
        encryptionConfiguration: {
          encryptionOption: 'INVALID_OPTION',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with enforceWorkGroupConfiguration explicitly set to false
  // ruleid: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupExplicitNoEnforcement', {
    name: 'query-results-explicit-no-enforcement',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: false,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
      },
    },
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with SSE_S3 encryption and enforcement
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupSSES3', {
    name: 'query-results-sse-s3',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  const kmsKey = new kms.Key(scope, 'AthenaQueryResultsKey');
  
  // Creating Athena WorkGroup with SSE_KMS encryption and enforcement
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupSSEKMS', {
    name: 'query-results-sse-kms',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_KMS',
          kmsKey: kmsKey.keyArn,
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  const kmsKey = new kms.Key(scope, 'AthenaQueryResultsKey');
  
  // Creating Athena WorkGroup with CSE_KMS encryption and enforcement
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupCSEKMS', {
    name: 'query-results-cse-kms',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'CSE_KMS',
          kmsKey: kmsKey.keyArn,
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with props object that includes encryption
  const workGroupProps = {
    name: 'query-results-props-with-encryption',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
    },
  };
  
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupPropsWithEncryption', workGroupProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating multiple Athena WorkGroups in a loop with encryption
  const workGroupNames = ['analytics', 'reporting', 'dashboard'];
  
  for (const name of workGroupNames) {
    // ok: typescript_cdk_athena_incomplete_encryption
    new athena.CfnWorkGroup(scope, `AthenaWorkGroup${name}`, {
      name: `query-results-${name}`,
      description: `WorkGroup for ${name} with encryption`,
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: true,
        resultConfiguration: {
          outputLocation: `s3://${outputBucket.bucketName}/${name}/`,
          encryptionConfiguration: {
            encryptionOption: 'SSE_S3',
          },
        },
      },
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  const kmsKey = new kms.Key(scope, 'AthenaQueryResultsKey');
  
  // Creating Athena WorkGroup with conditional encryption that is always included
  const includeEncryption = true;
  const workGroupConfig: any = {
    enforceWorkGroupConfiguration: true,
    resultConfiguration: {
      outputLocation: `s3://${outputBucket.bucketName}/results/`,
    },
  };
  
  if (includeEncryption) {
    workGroupConfig.resultConfiguration.encryptionConfiguration = {
      encryptionOption: 'SSE_KMS',
      kmsKey: kmsKey.keyArn,
    };
  }
  
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupConditionalEncryption', {
    name: 'query-results-conditional-encryption',
    workGroupConfiguration: workGroupConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption and additional configurations
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupAdditionalConfig', {
    name: 'query-results-additional-config',
    description: 'WorkGroup with encryption and additional configurations',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      publishCloudWatchMetricsEnabled: true,
      bytesScannedCutoffPerQuery: 10000000,
      requesterPaysEnabled: false,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  const kmsKey = new kms.Key(scope, 'AthenaQueryResultsKey');
  
  // Creating Athena WorkGroup with variable for encryption option
  const encryptionType = 'SSE_KMS';
  
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupVariableEncryption', {
    name: 'query-results-variable-encryption',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: encryptionType,
          kmsKey: kmsKey.keyArn,
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption configuration built separately
  const encryptionConfig = {
    encryptionOption: 'SSE_S3',
  };
  
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupSeparateEncryption', {
    name: 'query-results-separate-encryption',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: encryptionConfig,
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  const kmsKey = new kms.Key(scope, 'AthenaQueryResultsKey');
  
  // Creating Athena WorkGroup with encryption and tags
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupWithTags', {
    name: 'query-results-with-tags',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_KMS',
          kmsKey: kmsKey.keyArn,
        },
      },
    },
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Department', value: 'Analytics' },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption and result configuration overrides
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupWithOverrides', {
    name: 'query-results-with-overrides',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
        expectedBucketOwner: '123456789012',
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  const kmsKey = new kms.Key(scope, 'AthenaQueryResultsKey');
  
  // Creating Athena WorkGroup with encryption and engine version
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupWithEngineVersion', {
    name: 'query-results-with-engine-version',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      engineVersion: {
        selectedEngineVersion: 'Athena engine version 2',
      },
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_KMS',
          kmsKey: kmsKey.keyArn,
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption and query limit
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupWithQueryLimit', {
    name: 'query-results-with-query-limit',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      bytesScannedCutoffPerQuery: 10737418240, // 10GB
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption and custom IAM role
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupWithExecutionRole', {
    name: 'query-results-with-execution-role',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      executionRole: 'arn:aws:iam::123456789012:role/AthenaExecutionRole',
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const outputBucket = new s3.Bucket(scope, 'QueryResultsBucket');
  
  // Creating Athena WorkGroup with encryption and additional settings
  // ok: typescript_cdk_athena_incomplete_encryption
  new athena.CfnWorkGroup(scope, 'AthenaWorkGroupWithAdditionalSettings', {
    name: 'query-results-with-additional-settings',
    workGroupConfiguration: {
      enforceWorkGroupConfiguration: true,
      publishCloudWatchMetricsEnabled: true,
      requesterPaysEnabled: false,
      resultConfiguration: {
        outputLocation: `s3://${outputBucket.bucketName}/results/`,
        encryptionConfiguration: {
          encryptionOption: 'SSE_S3',
        },
      },
      customerContentEncryptionConfiguration: {
        kmsKey: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
      },
    },
    recursiveDeleteOption: true,
  });
}
// {/fact}