import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Firehose delivery stream without encryption
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      bufferingHints: {
        intervalInSeconds: 60,
        sizeInMBs: 5
      }
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Firehose delivery stream with explicit undefined encryption config
  const bucket = new s3.Bucket(scope, 'MyBucket2');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream2', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole2', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: undefined
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a Firehose delivery stream with null encryption config
  const bucket = new s3.Bucket(scope, 'MyBucket3');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream3', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole3', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: null as any
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Firehose delivery stream with Redshift destination but no encryption
  const bucket = new s3.Bucket(scope, 'MyBucket4');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream4', {
    redshiftDestinationConfiguration: {
      clusterJdbcurl: 'jdbc:redshift://redshift-cluster:5439/database',
      copyCommand: {
        dataTableName: 'table',
        copyOptions: 'CSV'
      },
      username: 'username',
      password: 'password',
      roleArn: new iam.Role(scope, 'FirehoseRole4', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'S3Role4', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      }
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Firehose delivery stream with ElasticSearch destination but no encryption
  const bucket = new s3.Bucket(scope, 'MyBucket5');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream5', {
    elasticsearchDestinationConfiguration: {
      indexName: 'index',
      roleArn: new iam.Role(scope, 'FirehoseRole5', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'S3Role5', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      },
      domainArn: 'arn:aws:es:region:account-id:domain/domain-name'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Firehose delivery stream with Splunk destination but no encryption
  const bucket = new s3.Bucket(scope, 'MyBucket6');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream6', {
    splunkDestinationConfiguration: {
      hECEndpoint: 'https://splunk-endpoint:8088',
      hECEndpointType: 'Raw',
      hECToken: 'splunk-token',
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'S3Role6', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      }
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Firehose delivery stream with HttpEndpoint destination but no encryption
  const bucket = new s3.Bucket(scope, 'MyBucket7');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream7', {
    httpEndpointDestinationConfiguration: {
      endpointConfiguration: {
        url: 'https://api.example.com',
        name: 'Example API'
      },
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'S3Role7', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      }
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Firehose delivery stream with Kinesis source but no encryption
  const kinesisStream = new kinesis.Stream(scope, 'SourceStream8');
  const bucket = new s3.Bucket(scope, 'MyBucket8');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream8', {
    kinesisStreamSourceConfiguration: {
      kinesisStreamArn: kinesisStream.streamArn,
      roleArn: new iam.Role(scope, 'SourceRole8', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'S3Role8', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Firehose delivery stream with empty properties object
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream9', {});
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Firehose delivery stream with extended S3 destination but no encryption
  const bucket = new s3.Bucket(scope, 'MyBucket10');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream10', {
    extendedS3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole10', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      processingConfiguration: {
        enabled: true,
        processors: [
          {
            type: 'Lambda',
            parameters: [
              {
                parameterName: 'LambdaArn',
                parameterValue: 'arn:aws:lambda:region:account:function:name'
              }
            ]
          }
        ]
      }
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Firehose delivery stream with props from variable but no encryption
  const bucket = new s3.Bucket(scope, 'MyBucket11');
  const props = {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole11', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    }
  };
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream11', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Firehose delivery stream with encryption config but empty key type
  const bucket = new s3.Bucket(scope, 'MyBucket12');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream12', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole12', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: ''
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Firehose delivery stream with encryption config but null key type
  const bucket = new s3.Bucket(scope, 'MyBucket13');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream13', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole13', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: null as any
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Firehose delivery stream with encryption config but undefined key type
  const bucket = new s3.Bucket(scope, 'MyBucket14');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream14', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole14', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: undefined
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Firehose delivery stream with empty object for encryption config
  const bucket = new s3.Bucket(scope, 'MyBucket15');
  
  // ruleid: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'MyDeliveryStream15', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'FirehoseRole15', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {}
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Firehose delivery stream with AWS managed KMS key encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket1');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream1', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole1', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Firehose delivery stream with customer managed KMS key encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket2');
  const key = new kms.Key(scope, 'CustomKey2');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream2', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole2', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'CUSTOMER_MANAGED_CMK',
      keyArn: key.keyArn
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Firehose delivery stream with Redshift destination and encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket3');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream3', {
    redshiftDestinationConfiguration: {
      clusterJdbcurl: 'jdbc:redshift://redshift-cluster:5439/database',
      copyCommand: {
        dataTableName: 'table',
        copyOptions: 'CSV'
      },
      username: 'username',
      password: 'password',
      roleArn: new iam.Role(scope, 'SecureFirehoseRole3', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'SecureS3Role3', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      }
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Firehose delivery stream with ElasticSearch destination and encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket4');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream4', {
    elasticsearchDestinationConfiguration: {
      indexName: 'index',
      roleArn: new iam.Role(scope, 'SecureFirehoseRole4', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'SecureS3Role4', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      },
      domainArn: 'arn:aws:es:region:account-id:domain/domain-name'
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a Firehose delivery stream with Splunk destination and encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket5');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream5', {
    splunkDestinationConfiguration: {
      hECEndpoint: 'https://splunk-endpoint:8088',
      hECEndpointType: 'Raw',
      hECToken: 'splunk-token',
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'SecureS3Role5', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      }
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Firehose delivery stream with HttpEndpoint destination and encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket6');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream6', {
    httpEndpointDestinationConfiguration: {
      endpointConfiguration: {
        url: 'https://api.example.com',
        name: 'Example API'
      },
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'SecureS3Role6', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      }
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Firehose delivery stream with Kinesis source and encryption
  const kinesisStream = new kinesis.Stream(scope, 'SecureSourceStream7');
  const bucket = new s3.Bucket(scope, 'SecureBucket7');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream7', {
    kinesisStreamSourceConfiguration: {
      kinesisStreamArn: kinesisStream.streamArn,
      roleArn: new iam.Role(scope, 'SecureSourceRole7', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureS3Role7', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Firehose delivery stream with extended S3 destination and encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket8');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream8', {
    extendedS3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole8', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      processingConfiguration: {
        enabled: true,
        processors: [
          {
            type: 'Lambda',
            parameters: [
              {
                parameterName: 'LambdaArn',
                parameterValue: 'arn:aws:lambda:region:account:function:name'
              }
            ]
          }
        ]
      }
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Firehose delivery stream with props from variable and encryption
  const bucket = new s3.Bucket(scope, 'SecureBucket9');
  const props = {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole9', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  };
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream9', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Firehose delivery stream with customer managed key and alias
  const bucket = new s3.Bucket(scope, 'SecureBucket10');
  const key = new kms.Key(scope, 'CustomKey10', {
    enableKeyRotation: true,
    description: 'KMS key for Firehose encryption'
  });
  new kms.Alias(scope, 'KeyAlias10', {
    aliasName: 'alias/firehose-encryption-key',
    targetKey: key
  });
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream10', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole10', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'CUSTOMER_MANAGED_CMK',
      keyArn: key.keyArn
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Firehose delivery stream with encryption and dynamic configuration
  const bucket = new s3.Bucket(scope, 'SecureBucket11');
  const keyType = 'AWS_OWNED_CMK';
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream11', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole11', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: keyType
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Firehose delivery stream with encryption and conditional configuration
  const bucket = new s3.Bucket(scope, 'SecureBucket12');
  const useCustomKey = false;
  const key = new kms.Key(scope, 'CustomKey12');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream12', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole12', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: useCustomKey ? 'CUSTOMER_MANAGED_CMK' : 'AWS_OWNED_CMK',
      keyArn: useCustomKey ? key.keyArn : undefined
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Firehose delivery stream with encryption and multiple destinations
  const bucket = new s3.Bucket(scope, 'SecureBucket13');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream13', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole13', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    amazonopensearchserviceDestinationConfiguration: {
      indexName: 'index',
      roleArn: new iam.Role(scope, 'OpenSearchRole13', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      s3Configuration: {
        bucketArn: bucket.bucketArn,
        roleArn: new iam.Role(scope, 'SecureS3Role13', {
          assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
        }).roleArn
      },
      domainArn: 'arn:aws:es:region:account-id:domain/domain-name'
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Firehose delivery stream with encryption and advanced configuration
  const bucket = new s3.Bucket(scope, 'SecureBucket14');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream14', {
    extendedS3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole14', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn,
      bufferingHints: {
        intervalInSeconds: 60,
        sizeInMBs: 5
      },
      compressionFormat: 'GZIP',
      encryptionConfiguration: {
        noEncryptionConfig: 'NoEncryption'
      },
      cloudWatchLoggingOptions: {
        enabled: true,
        logGroupName: 'firehose-logs',
        logStreamName: 'delivery-stream'
      }
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Firehose delivery stream with encryption and tags
  const bucket = new s3.Bucket(scope, 'SecureBucket15');
  
  // ok: typescript_cdk_kinesis_data_firehose_sse
  new firehose.CfnDeliveryStream(scope, 'SecureDeliveryStream15', {
    s3DestinationConfiguration: {
      bucketArn: bucket.bucketArn,
      roleArn: new iam.Role(scope, 'SecureFirehoseRole15', {
        assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com')
      }).roleArn
    },
    deliveryStreamEncryptionConfigurationInput: {
      keyType: 'AWS_OWNED_CMK'
    },
    tags: [
      {
        key: 'Environment',
        value: 'Production'
      },
      {
        key: 'SecurityCompliance',
        value: 'Enabled'
      }
    ]
  });
}
// {/fact}