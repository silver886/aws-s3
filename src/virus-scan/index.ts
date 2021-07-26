import * as cdk from '@aws-cdk/core';

import * as autoscaling from '@aws-cdk/aws-autoscaling';
import * as cloudwatch from '@aws-cdk/aws-cloudwatch';
import * as cloudwatchActions from '@aws-cdk/aws-cloudwatch-actions';
import * as ec2 from '@aws-cdk/aws-ec2';
import * as iam from '@aws-cdk/aws-iam';
import * as lambda from '@aws-cdk/aws-lambda';
import * as logs from '@aws-cdk/aws-logs';
import type * as s3 from '@aws-cdk/aws-s3';
import * as sCdk from '@silver886/aws-cdk';
import * as sEc2 from '@silver886/aws-ec2';
import * as sns from '@aws-cdk/aws-sns';
import * as sqs from '@aws-cdk/aws-sqs';

import * as ec2Helper from './ec2/';

export interface VirusScanProps {
    readonly action: {
        readonly deleteInfected: boolean;
        readonly reportClean: boolean;
        readonly tagKey?: string;
    };
    readonly autoScaling: {
        readonly instanceType: ec2.InstanceType;
        readonly spotPrice?: number;
        readonly volumeSize: number;
        readonly swapSize: number;
        readonly minimum: number;
        readonly maximum: number;
    };

    readonly ec2Vpc?: ec2.IVpc;
    readonly snsTopic?: sns.ITopic;
}

export class VirusScan extends cdk.Construct {
    public readonly ec2Vpc: ec2.IVpc;

    public readonly snsTopic: sns.ITopic;

    private readonly iamRole: iam.Role;

    private readonly iamPolicyStatement: iam.PolicyStatement = new iam.PolicyStatement({
        effect:  iam.Effect.ALLOW,
        actions: [
            's3:PutBucketNotification',
        ],
    });

    private readonly lambdaFunction: {
        readonly sqsGrantSend: lambda.Function;
        readonly s3PutNotification: lambda.Function;
    };

    private readonly props: VirusScanProps;

    // eslint-disable-next-line max-lines-per-function, max-statements
    public constructor(scope: cdk.Construct, id: string, props: VirusScanProps) {
        super(scope, id);
        this.props = props;

        /* eslint-disable @typescript-eslint/no-magic-numbers */
        if (props.autoScaling.minimum < 0) throw new Error('AutoScaling.minimum must be >= 0');
        if (props.autoScaling.maximum < 1) throw new Error('AutoScaling.maximum must be >= 1');
        if (props.autoScaling.spotPrice && props.autoScaling.spotPrice < 0) throw new Error('AutoScaling.spotPrice must be a positive number');
        if (props.autoScaling.volumeSize < 8 || props.autoScaling.volumeSize > 1024) throw new Error('AutoScaling.volumeSize must be in the range [8-1024]');
        if (props.autoScaling.swapSize >= props.autoScaling.volumeSize ||
            props.autoScaling.swapSize < 0 || props.autoScaling.swapSize > 8) throw new Error('AutoScaling.swapSize must be in the range [0-8]');
        /* eslint-enable @typescript-eslint/no-magic-numbers */

        const ec2Vpc = props.ec2Vpc ?? new ec2.Vpc(this, 'vpc', {
            subnetConfiguration: [
                {
                    cidrMask:   24,
                    name:       'default',
                    subnetType: ec2.SubnetType.PUBLIC,
                },
            ],
        });
        this.ec2Vpc = ec2Vpc;

        const snsTopic = props.snsTopic ?? new sns.Topic(this, 'topic', {
            displayName: `${cdk.Stack.of(scope).stackName}: Virus scan notification`,
        });
        this.snsTopic = snsTopic;

        const deadLetterQueue = new sqs.Queue(this, 'queue-dead-letter', {
            retentionPeriod: cdk.Duration.days(14), // eslint-disable-line @typescript-eslint/no-magic-numbers
        });

        const scanQueue = new sqs.Queue(this, 'queue', {
            visibilityTimeout: cdk.Duration.minutes(5), // eslint-disable-line @typescript-eslint/no-magic-numbers
            deadLetterQueue:   {
                queue:           deadLetterQueue,
                maxReceiveCount: 3,
            },
        });

        this.lambdaFunction = {
            sqsGrantSend: new lambda.Function(scanQueue, 'lambda', {
                description:   `${cdk.Stack.of(scope).stackName}: SQS Queue send message permission`,
                initialPolicy: [
                    new iam.PolicyStatement({
                        effect:  iam.Effect.ALLOW,
                        actions: [
                            'sqs:GetQueueAttributes',
                            'sqs:SetQueueAttributes',
                        ],
                        resources: [
                            scanQueue.queueArn,
                        ],
                    }),
                ],
                environment: {
                    sqsArn: scanQueue.queueArn,
                    sqsUrl: scanQueue.queueUrl,
                },
                runtime: lambda.Runtime.NODEJS_14_X,
                code:    lambda.Code.fromAsset(`${__dirname}/lambda/sqs-grant-send`),
                handler: 'bundle.handler',
            }),
            s3PutNotification: new lambda.Function(scanQueue, 'lambda', {
                description: `${cdk.Stack.of(scope).stackName}: S3 Object creation notification configuration`,
                environment: {
                    sqsArn: scanQueue.queueArn,
                },
                runtime: lambda.Runtime.NODEJS_14_X,
                code:    lambda.Code.fromAsset(`${__dirname}/lambda/s3-put-notification`),
                handler: 'bundle.handler',
            }),
        };

        const logGroup = new logs.LogGroup(this, 'log', {
            retention: logs.RetentionDays.FIVE_YEARS,
        });

        const role = new iam.Role(this, 'role', {
            assumedBy:       new iam.ServicePrincipal('ec2.amazonaws.com'),
            description:     `${cdk.Stack.of(this).stackName}: EC2 virus scanner`,
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
                iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
            ],
            inlinePolicies: {
                sqs: new iam.PolicyDocument({
                    statements: [
                        new iam.PolicyStatement({
                            effect:  iam.Effect.ALLOW,
                            actions: [
                                'sqs:DeleteMessage',
                                'sqs:ReceiveMessage',
                            ],
                            resources: [
                                scanQueue.queueArn,
                            ],
                        }),
                    ],
                }),
                sns: new iam.PolicyDocument({
                    statements: [
                        new iam.PolicyStatement({
                            effect:  iam.Effect.ALLOW,
                            actions: [
                                'sns:Publish',
                            ],
                            resources: [
                                snsTopic.topicArn,
                            ],
                        }),
                    ],
                }),
            },
        });
        this.iamRole = role;

        const group = new autoscaling.AutoScalingGroup(this, 'group', {
            vpc:        ec2Vpc,
            vpcSubnets: {
                subnetType: ec2.SubnetType.PUBLIC,
            },
            allowAllOutbound: true,
            role,
            minCapacity:      props.autoScaling.minimum,
            maxCapacity:      props.autoScaling.maximum,
            blockDevices:     [{
                deviceName: '/dev/xvda',
                volume:     autoscaling.BlockDeviceVolume.ebs(props.autoScaling.volumeSize, {
                    encrypted: true,
                }),
            }],
            instanceType: props.autoScaling.instanceType,
            spotPrice:    props.autoScaling.spotPrice ? props.autoScaling.spotPrice.toString() : undefined, // eslint-disable-line no-undefined
            machineImage: new ec2.AmazonLinuxImage({
                generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            }),
            init: ec2.CloudFormationInit.fromConfigSets({
                configSets: {
                    default: [
                        ...props.autoScaling.swapSize ? ['swap'] : [],
                        'cloudwatch',
                        'enableEpel',
                        'installEpel',
                        'config',
                    ],
                },
                configs: {
                    swap:       sEc2.init.config.swap.generate(props.autoScaling.swapSize),
                    // eslint-disable-next-line max-len
                    cloudwatch: sEc2.init.config.cloudwatch.agent(sEc2.init.config.cloudwatch.Arch.X86_64, sEc2.init.config.cloudwatch.Os.AMAZON_LINUX_AND_AMAZON_LINUX_2, {
                        /* eslint-disable @typescript-eslint/naming-convention */
                        logs: {
                            log_stream_name: '{instance_id}',
                            logs_collected:  {
                                files: {
                                    collect_list: [{
                                        file_path:        '/var/log/cfn-init-cmd.log',
                                        log_group_name:   logGroup.logGroupName,
                                        log_stream_name:  '{instance_id}/var/log/cfn-init-cmd.log',
                                        timestamp_format: '%Y-%m-%d %H:%M:%S',
                                    }, {
                                        file_path:        '/var/log/cfn-init.log',
                                        log_group_name:   logGroup.logGroupName,
                                        log_stream_name:  '{instance_id}/var/log/cfn-init.log',
                                        timestamp_format: '%Y-%m-%d %H:%M:%S',
                                    }, {
                                        file_path:        '/var/log/yum.log',
                                        log_group_name:   logGroup.logGroupName,
                                        log_stream_name:  '{instance_id}/var/log/yum.log',
                                        timestamp_format: '%b %d %H:%M:%S',
                                    }, {
                                        file_path:        '/var/log/messages',
                                        log_group_name:   logGroup.logGroupName,
                                        log_stream_name:  '{instance_id}/var/log/messages',
                                        timestamp_format: '%b %-d %H:%M:%S',
                                    }],
                                },
                            },
                        },
                        metrics: {
                            namespace:         `${cdk.Stack.of(this).stackName}/VirusScan`,
                            append_dimensions: {
                                InstanceType:         '${aws:InstanceType}',
                                AutoScalingGroupName: '${aws:AutoScalingGroupName}',
                            },
                            metrics_collected: {
                                mem: {
                                    measurement: [
                                        'mem_used_percent',
                                    ],
                                },
                                swap: {
                                    measurement: [
                                        'swap_used_percent',
                                    ],
                                },
                                disk: {
                                    resources: [
                                        '/',
                                    ],
                                    measurement: [
                                        'used_percent',
                                    ],
                                    drop_device: true,
                                },
                            },
                        },
                        /* eslint-enable @typescript-eslint/naming-convention */
                    }),
                    enableEpel:  sEc2.init.config.epel.enable(),
                    installEpel: new ec2.InitConfig([
                        ec2.InitPackage.yum('epel-release'),
                    ]),
                    config: ec2Helper.init.config.clam.service({
                        deleteInfected: props.action.deleteInfected,
                        reportClean:    props.action.reportClean,
                        tagKey:         props.action.tagKey,
                        region:         cdk.Stack.of(this).region,
                        queueUrl:       scanQueue.queueUrl,
                        topicArn:       snsTopic.topicArn,
                        volumeSize:     props.autoScaling.volumeSize,
                    }),
                },
            }),
            signals:       autoscaling.Signals.waitForAll(),
            notifications: [{
                topic: snsTopic,
            }],
        });

        const scalingInterval = 5;
        const stepScalingUp = new autoscaling.StepScalingAction(group, 'step_scaling-up', {
            autoScalingGroup:        group,
            estimatedInstanceWarmup: cdk.Duration.minutes(scalingInterval),
            adjustmentType:          autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
            metricAggregationType:   autoscaling.MetricAggregationType.MAXIMUM,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 0,
            upperBound: 25,
            adjustment: 1,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 25,
            upperBound: 100,
            adjustment: 2,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 100,
            upperBound: 400,
            adjustment: 4,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 400,
            upperBound: 1600,
            adjustment: 8,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 1600,
            upperBound: 6400,
            adjustment: 16,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 6400,
            upperBound: 25600,
            adjustment: 32,
        });
        stepScalingUp.addAdjustment({
            lowerBound: 25600,
            adjustment: 64,
        });

        const stepScalingDown = new autoscaling.StepScalingAction(group, 'step_scaling-down', {
            autoScalingGroup:       group,
            adjustmentType:         autoscaling.AdjustmentType.PERCENT_CHANGE_IN_CAPACITY,
            minAdjustmentMagnitude: 1,
        });
        stepScalingDown.addAdjustment({
            lowerBound: 0,
            adjustment: -25,
        });

        const scanQueueVisibleMessagesPeriod = 5;
        new cloudwatch.Alarm(scanQueue, 'alarm-number_of_visible_messages_too_high', {
            alarmDescription: `${cdk.Stack.of(this).stackName}: SQS maximum number of visible messages over last ${scanQueueVisibleMessagesPeriod} minutes higher than 1`,
            metric:           new cloudwatch.Metric({
                namespace:  'AWS/SQS',
                metricName: 'ApproximateNumberOfMessagesVisible',
                period:     cdk.Duration.minutes(scanQueueVisibleMessagesPeriod),
                statistic:  'Maximum',
                dimensions: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: scanQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            threshold:          1,
            evaluationPeriods:  1,
            treatMissingData:   cloudwatch.TreatMissingData.BREACHING,
        }).addAlarmAction(new cloudwatchActions.AutoScalingAction(stepScalingUp));

        new cloudwatch.Alarm(scanQueue, 'alarm-number_of_visible_messages_too_low', {
            alarmDescription: `${cdk.Stack.of(this).stackName}: SQS maximum number of visible messages over last ${scanQueueVisibleMessagesPeriod} minutes lower than 1`,
            metric:           new cloudwatch.Metric({
                namespace:  'AWS/SQS',
                metricName: 'ApproximateNumberOfMessagesVisible',
                period:     cdk.Duration.minutes(scanQueueVisibleMessagesPeriod),
                statistic:  'Maximum',
                dimensions: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: scanQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
            threshold:          1,
            evaluationPeriods:  1,
            treatMissingData:   cloudwatch.TreatMissingData.BREACHING,
        }).addAlarmAction(new cloudwatchActions.AutoScalingAction(stepScalingDown));

        const statusAlarmPeriod = 1;
        new cloudwatch.Alarm(deadLetterQueue, 'alarm-has_messages', {
            alarmDescription: `${cdk.Stack.of(this).stackName}: SQS dead letter queue has messages`,
            metric:           new cloudwatch.Metric({
                namespace:  'AWS/SQS',
                metricName: 'ApproximateNumberOfMessagesVisible',
                period:     cdk.Duration.minutes(statusAlarmPeriod),
                statistic:  'Sum',
                dimensions: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: deadLetterQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            threshold:          1,
            evaluationPeriods:  1,
            treatMissingData:   cloudwatch.TreatMissingData.NOT_BREACHING,
        }).addAlarmAction(new cloudwatchActions.SnsAction(snsTopic));

        const scanQueueMessageAge = 1;
        new cloudwatch.Alarm(scanQueue, `alarm-contains_messages_older_than_${scanQueueMessageAge}_hour`, {
            alarmDescription: `${cdk.Stack.of(this).stackName}: SQS scan queue contains messages older than ${scanQueueMessageAge} hour`,
            metric:           new cloudwatch.Metric({
                namespace:  'AWS/SQS',
                metricName: 'ApproximateAgeOfOldestMessage',
                period:     cdk.Duration.minutes(statusAlarmPeriod),
                statistic:  'Maximum',
                dimensions: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: scanQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            threshold:          cdk.Duration.hours(scanQueueMessageAge).toSeconds(),
            evaluationPeriods:  1,
            treatMissingData:   cloudwatch.TreatMissingData.NOT_BREACHING,
        }).addAlarmAction(new cloudwatchActions.SnsAction(snsTopic));
    }

    // eslint-disable-next-line max-lines-per-function
    public hookS3Bucket(bucket: s3.Bucket): sCdk.Name {
        const nestedScope = new sCdk.Name(bucket, 'virus-scanner');

        const {iamPolicyStatement} = this;
        iamPolicyStatement.addResources(bucket.bucketArn);
        this.lambdaFunction.s3PutNotification.addToRolePolicy(iamPolicyStatement);

        // eslint-disable-next-line no-new
        new cdk.CustomResource(nestedScope, 'custom-resource-sqs', {
            resourceType: 'Custom::SQS-updateQueuePolicy',
            properties:   {
                account: cdk.Stack.of(bucket).account,
                s3Arn:   bucket.bucketArn,
            },
            serviceToken: this.lambdaFunction.sqsGrantSend.functionArn,
        });

        // eslint-disable-next-line no-new
        new cdk.CustomResource(nestedScope, 'custom-resource-s3', {
            resourceType: 'Custom::S3-updateBucketNotification',
            properties:   {
                account: cdk.Stack.of(bucket).account,
                s3Name:  bucket.bucketName,
            },
            serviceToken: this.lambdaFunction.s3PutNotification.functionArn,
        });

        this.iamRole.attachInlinePolicy(new iam.Policy(nestedScope, 'policy-read', {
            document: new iam.PolicyDocument({
                statements: [
                    new iam.PolicyStatement({
                        effect:  iam.Effect.ALLOW,
                        actions: [
                            's3:GetObject*',
                        ],
                        resources: [
                            bucket.arnForObjects('*'),
                        ],
                    }),
                    new iam.PolicyStatement({
                        effect:  iam.Effect.ALLOW,
                        actions: [
                            's3:ListBucket*',
                        ],
                        resources: [
                            bucket.bucketArn,
                        ],
                    }),
                ],
            }),
        }));

        if (this.props.action.deleteInfected) {
            this.iamRole.attachInlinePolicy(new iam.Policy(nestedScope, 'policy-delete', {
                document: new iam.PolicyDocument({
                    statements: [
                        new iam.PolicyStatement({
                            effect:  iam.Effect.ALLOW,
                            actions: [
                                's3:DeleteObject*',
                            ],
                            resources: [
                                bucket.arnForObjects('*'),
                            ],
                        }),
                    ],
                }),
            }));
        }

        if (this.props.action.tagKey) {
            this.iamRole.attachInlinePolicy(new iam.Policy(nestedScope, 'policy-tag', {
                document: new iam.PolicyDocument({
                    statements: [
                        new iam.PolicyStatement({
                            effect:  iam.Effect.ALLOW,
                            actions: [
                                's3:PutObjectTagging',
                                's3:PutObjectVersionTagging',
                            ],
                            resources: [
                                bucket.arnForObjects('*'),
                            ],
                            conditions: {
                                /* eslint-disable @typescript-eslint/naming-convention */
                                'ForAllValues:StringLike': {
                                    's3:RequestObjectTagKeys': this.props.action.tagKey,
                                },
                                /* eslint-enable @typescript-eslint/naming-convention */
                            },
                        }),
                    ],
                }),
            }));
        }

        return nestedScope;
    }
}
