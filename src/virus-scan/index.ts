import {
    CustomResource as CdkCustomResource,
    Duration as CdkDuration,
    Stack as CdkStack,
    aws_autoscaling as cdkAutoscaling,
    aws_cloudwatch as cdkCloudwatch,
    aws_cloudwatch_actions as cdkCloudwatchActions,
    custom_resources as cdkCustomResources,
    aws_ec2 as cdkEc2,
    aws_iam as cdkIam,
    aws_lambda as cdkLambda,
    aws_logs as cdkLogs,
    aws_sns as cdkSns,
    aws_sqs as cdkSqs,
} from 'aws-cdk-lib';
import {
    Construct as AwsConstruct,
} from 'constructs';
import type {
    aws_s3 as cdkS3,
} from 'aws-cdk-lib';

import * as sCdk from '@silver886/aws-cdk';
import * as sEc2 from '@silver886/aws-ec2';

import * as ec2Helper from './ec2/';

export interface VirusScanProps {
    readonly action: {
        readonly deleteInfected: boolean;
        readonly reportClean: boolean;
        readonly tagKey?: string;
    };
    readonly autoScaling: {
        readonly instanceType: cdkEc2.InstanceType;
        readonly spotPrice?: number;
        readonly volumeSize: number;
        readonly swapSize: number;
        readonly minimum: number;
        readonly maximum: number;
    };

    readonly ec2Vpc?: cdkEc2.IVpc;
    readonly snsTopic?: cdkSns.ITopic;
}

export class VirusScan extends AwsConstruct {
    public readonly ec2Vpc: cdkEc2.IVpc;

    public readonly snsTopic: cdkSns.ITopic;

    private readonly iamRole: cdkIam.Role;

    private readonly lambdaFunction: {
        readonly sqsGrantSend: cdkLambda.Function;
        readonly s3PutNotification: cdkLambda.Function;
    };

    private readonly props: VirusScanProps;

    // eslint-disable-next-line max-lines-per-function, max-statements
    public constructor(scope: AwsConstruct, id: string, props: VirusScanProps) {
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

        const ec2Vpc = props.ec2Vpc ?? new cdkEc2.Vpc(this, 'vpc', {
            subnetConfiguration: [
                {
                    cidrMask:   24,
                    name:       'default',
                    subnetType: cdkEc2.SubnetType.PUBLIC,
                },
            ],
        });
        this.ec2Vpc = ec2Vpc;

        const snsTopic = props.snsTopic ?? new cdkSns.Topic(this, 'topic', {
            displayName: `${CdkStack.of(scope).stackName}: Virus scan notification`,
        });
        this.snsTopic = snsTopic;

        const deadLetterQueue = new cdkSqs.Queue(this, 'queue-dead-letter', {
            retentionPeriod: CdkDuration.days(14), // eslint-disable-line @typescript-eslint/no-magic-numbers
        });

        const scanQueue = new cdkSqs.Queue(this, 'queue', {
            visibilityTimeout: CdkDuration.minutes(5), // eslint-disable-line @typescript-eslint/no-magic-numbers
            deadLetterQueue:   {
                queue:           deadLetterQueue,
                maxReceiveCount: 3,
            },
        });

        this.lambdaFunction = {
            sqsGrantSend: new cdkLambda.Function(scanQueue, 'lambda-sqs-grant-send', {
                description:   `${CdkStack.of(scope).stackName}: SQS Queue send message permission`,
                initialPolicy: [
                    new cdkIam.PolicyStatement({
                        effect:  cdkIam.Effect.ALLOW,
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
                runtime: cdkLambda.Runtime.NODEJS_14_X,
                code:    cdkLambda.Code.fromAsset(`${__dirname}/lambda/sqs-grant-send`),
                handler: 'bundle.handler',
            }),
            s3PutNotification: new cdkLambda.Function(scanQueue, 'lambda-s3-put-notification', {
                description: `${CdkStack.of(scope).stackName}: S3 Object creation notification configuration`,
                environment: {
                    sqsArn: scanQueue.queueArn,
                },
                runtime: cdkLambda.Runtime.NODEJS_14_X,
                code:    cdkLambda.Code.fromAsset(`${__dirname}/lambda/s3-put-notification`),
                handler: 'bundle.handler',
            }),
        };

        const logGroup = new cdkLogs.LogGroup(this, 'log', {
            retention: cdkLogs.RetentionDays.FIVE_YEARS,
        });

        const role = new cdkIam.Role(this, 'role', {
            assumedBy:       new cdkIam.ServicePrincipal('cdkEc2.amazonaws.com'),
            description:     `${CdkStack.of(this).stackName}: EC2 virus scanner`,
            managedPolicies: [
                cdkIam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
                cdkIam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
            ],
            inlinePolicies: {
                sqs: new cdkIam.PolicyDocument({
                    statements: [
                        new cdkIam.PolicyStatement({
                            effect:  cdkIam.Effect.ALLOW,
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
                sns: new cdkIam.PolicyDocument({
                    statements: [
                        new cdkIam.PolicyStatement({
                            effect:  cdkIam.Effect.ALLOW,
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

        const group = new cdkAutoscaling.AutoScalingGroup(this, 'group', {
            vpc:        ec2Vpc,
            vpcSubnets: {
                subnetType: cdkEc2.SubnetType.PUBLIC,
            },
            allowAllOutbound: true,
            role,
            minCapacity:      props.autoScaling.minimum,
            maxCapacity:      props.autoScaling.maximum,
            blockDevices:     [{
                deviceName: '/dev/xvda',
                volume:     cdkAutoscaling.BlockDeviceVolume.ebs(props.autoScaling.volumeSize, {
                    encrypted: true,
                }),
            }],
            instanceType: props.autoScaling.instanceType,
            spotPrice:    props.autoScaling.spotPrice ? props.autoScaling.spotPrice.toString() : undefined, // eslint-disable-line no-undefined
            machineImage: new cdkEc2.AmazonLinuxImage({
                generation: cdkEc2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            }),
            init: cdkEc2.CloudFormationInit.fromConfigSets({
                configSets: {
                    default: [
                        ...props.autoScaling.swapSize ? ['swap'] : [],
                        'cloudwatch',
                        'enableEpel',
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
                            namespace:     `${CdkStack.of(this).stackName}/VirusScan`,
                            dimensionsMap: {
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
                    enableEpel: sEc2.init.config.epel.enable(),
                    config:     ec2Helper.init.config.clam.service({
                        deleteInfected: props.action.deleteInfected,
                        reportClean:    props.action.reportClean,
                        tagKey:         props.action.tagKey,
                        region:         CdkStack.of(this).region,
                        queueUrl:       scanQueue.queueUrl,
                        topicArn:       snsTopic.topicArn,
                        volumeSize:     props.autoScaling.volumeSize,
                    }),
                },
            }),
            signals:       cdkAutoscaling.Signals.waitForAll(),
            notifications: [{
                topic: snsTopic,
            }],
        });

        const scalingInterval = 5;
        const stepScalingUp = new cdkAutoscaling.StepScalingAction(group, 'step_scaling-up', {
            autoScalingGroup:        group,
            estimatedInstanceWarmup: CdkDuration.minutes(scalingInterval),
            adjustmentType:          cdkAutoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
            metricAggregationType:   cdkAutoscaling.MetricAggregationType.MAXIMUM,
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

        const stepScalingDown = new cdkAutoscaling.StepScalingAction(group, 'step_scaling-down', {
            autoScalingGroup:       group,
            adjustmentType:         cdkAutoscaling.AdjustmentType.PERCENT_CHANGE_IN_CAPACITY,
            minAdjustmentMagnitude: 1,
        });
        stepScalingDown.addAdjustment({
            lowerBound: 0,
            adjustment: -25,
        });

        const scanQueueVisibleMessagesPeriod = 5;
        new cdkCloudwatch.Alarm(scanQueue, 'alarm-number_of_visible_messages_too_high', {
            alarmDescription: `${CdkStack.of(this).stackName}: SQS maximum number of visible messages over last ${scanQueueVisibleMessagesPeriod} minutes higher than 1`,
            metric:           new cdkCloudwatch.Metric({
                namespace:     'AWS/SQS',
                metricName:    'ApproximateNumberOfMessagesVisible',
                period:        CdkDuration.minutes(scanQueueVisibleMessagesPeriod),
                statistic:     'Maximum',
                dimensionsMap: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: scanQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cdkCloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            threshold:          1,
            evaluationPeriods:  1,
            treatMissingData:   cdkCloudwatch.TreatMissingData.BREACHING,
        }).addAlarmAction(new cdkCloudwatchActions.AutoScalingAction(stepScalingUp));

        new cdkCloudwatch.Alarm(scanQueue, 'alarm-number_of_visible_messages_too_low', {
            alarmDescription: `${CdkStack.of(this).stackName}: SQS maximum number of visible messages over last ${scanQueueVisibleMessagesPeriod} minutes lower than 1`,
            metric:           new cdkCloudwatch.Metric({
                namespace:     'AWS/SQS',
                metricName:    'ApproximateNumberOfMessagesVisible',
                period:        CdkDuration.minutes(scanQueueVisibleMessagesPeriod),
                statistic:     'Maximum',
                dimensionsMap: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: scanQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cdkCloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
            threshold:          1,
            evaluationPeriods:  1,
            treatMissingData:   cdkCloudwatch.TreatMissingData.BREACHING,
        }).addAlarmAction(new cdkCloudwatchActions.AutoScalingAction(stepScalingDown));

        const statusAlarmPeriod = 1;
        new cdkCloudwatch.Alarm(deadLetterQueue, 'alarm-has_messages', {
            alarmDescription: `${CdkStack.of(this).stackName}: SQS dead letter queue has messages`,
            metric:           new cdkCloudwatch.Metric({
                namespace:     'AWS/SQS',
                metricName:    'ApproximateNumberOfMessagesVisible',
                period:        CdkDuration.minutes(statusAlarmPeriod),
                statistic:     'Sum',
                dimensionsMap: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: deadLetterQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cdkCloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            threshold:          1,
            evaluationPeriods:  1,
            treatMissingData:   cdkCloudwatch.TreatMissingData.NOT_BREACHING,
        }).addAlarmAction(new cdkCloudwatchActions.SnsAction(snsTopic));

        const scanQueueMessageAge = 1;
        new cdkCloudwatch.Alarm(scanQueue, `alarm-contains_messages_older_than_${scanQueueMessageAge}_hour`, {
            alarmDescription: `${CdkStack.of(this).stackName}: SQS scan queue contains messages older than ${scanQueueMessageAge} hour`,
            metric:           new cdkCloudwatch.Metric({
                namespace:     'AWS/SQS',
                metricName:    'ApproximateAgeOfOldestMessage',
                period:        CdkDuration.minutes(statusAlarmPeriod),
                statistic:     'Maximum',
                dimensionsMap: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    QueueName: scanQueue.queueName,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            }),
            comparisonOperator: cdkCloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            threshold:          CdkDuration.hours(scanQueueMessageAge).toSeconds(),
            evaluationPeriods:  1,
            treatMissingData:   cdkCloudwatch.TreatMissingData.NOT_BREACHING,
        }).addAlarmAction(new cdkCloudwatchActions.SnsAction(snsTopic));
    }

    // eslint-disable-next-line max-lines-per-function, max-statements
    public hookS3Bucket(scope: AwsConstruct, bucket: cdkS3.IBucket): sCdk.Name {
        const nestedScope = new sCdk.Name(scope, 'virus-scanner');

        const s3NotificationPolicy = new sCdk.Name(nestedScope, 's3-notification-policy');
        const s3PolicySdkCall: cdkCustomResources.AwsSdkCall = {
            service:    'IAM',
            action:     'putRolePolicy',
            parameters: {
                /* eslint-disable @typescript-eslint/naming-convention */
                RoleName:       this.lambdaFunction.s3PutNotification.role?.roleName,
                PolicyName:     s3NotificationPolicy.logical,
                PolicyDocument: JSON.stringify(new cdkIam.PolicyDocument({
                    statements: [
                        new cdkIam.PolicyStatement({
                            effect:  cdkIam.Effect.ALLOW,
                            actions: [
                                's3:GetBucketNotification',
                                's3:PutBucketNotification',
                            ],
                            resources: [
                                bucket.bucketArn,
                            ],
                        }),
                    ],
                })),
                /* eslint-enable @typescript-eslint/naming-convention */
            },
            physicalResourceId: cdkCustomResources.PhysicalResourceId.of(s3NotificationPolicy.node.addr),
        };
        const s3Policy = new cdkCustomResources.AwsCustomResource(s3NotificationPolicy, 'custom-resource', {
            resourceType: 'Custom::IAM-putRolePolicy',
            onCreate:     s3PolicySdkCall,
            onUpdate:     s3PolicySdkCall,
            onDelete:     {
                ...s3PolicySdkCall,
                action:     'deleteRolePolicy',
                parameters: {
                    /* eslint-disable @typescript-eslint/naming-convention */
                    RoleName:   this.lambdaFunction.s3PutNotification.role?.roleName,
                    PolicyName: s3NotificationPolicy.logical,
                    /* eslint-enable @typescript-eslint/naming-convention */
                },
            },
            policy: cdkCustomResources.AwsCustomResourcePolicy.fromSdkCalls({
                resources: [
                    this.lambdaFunction.s3PutNotification.role?.roleArn ?? '',
                ],
            }),
        });

        const sqsPolicy = new CdkCustomResource(nestedScope, 'custom-resource-sqs', {
            resourceType: 'Custom::SQS-updateQueuePolicy',
            properties:   {
                account: CdkStack.of(bucket).account,
                s3Arn:   bucket.bucketArn,
            },
            serviceToken: this.lambdaFunction.sqsGrantSend.functionArn,
        });
        sqsPolicy.node.addDependency(s3Policy);

        // eslint-disable-next-line no-new
        new CdkCustomResource(nestedScope, 'custom-resource-s3', {
            resourceType: 'Custom::S3-updateBucketNotification',
            properties:   {
                account: CdkStack.of(bucket).account,
                s3Name:  bucket.bucketName,
            },
            serviceToken: this.lambdaFunction.s3PutNotification.functionArn,
        }).node.addDependency(new sCdk.Delay(nestedScope, 'delay', {
            dependencies: [sqsPolicy],
        }));

        this.iamRole.attachInlinePolicy(new cdkIam.Policy(nestedScope, 'policy-read', {
            statements: [
                new cdkIam.PolicyStatement({
                    effect:  cdkIam.Effect.ALLOW,
                    actions: [
                        's3:GetObject*',
                    ],
                    resources: [
                        bucket.arnForObjects('*'),
                    ],
                }),
                new cdkIam.PolicyStatement({
                    effect:  cdkIam.Effect.ALLOW,
                    actions: [
                        's3:ListBucket*',
                    ],
                    resources: [
                        bucket.bucketArn,
                    ],
                }),
            ],
        }));

        if (this.props.action.deleteInfected) {
            this.iamRole.attachInlinePolicy(new cdkIam.Policy(nestedScope, 'policy-delete', {
                statements: [
                    new cdkIam.PolicyStatement({
                        effect:  cdkIam.Effect.ALLOW,
                        actions: [
                            's3:DeleteObject*',
                        ],
                        resources: [
                            bucket.arnForObjects('*'),
                        ],
                    }),
                ],
            }));
        }

        if (this.props.action.tagKey) {
            this.iamRole.attachInlinePolicy(new cdkIam.Policy(nestedScope, 'policy-tag', {
                statements: [
                    new cdkIam.PolicyStatement({
                        effect:  cdkIam.Effect.ALLOW,
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
            }));
        }

        return nestedScope;
    }
}
