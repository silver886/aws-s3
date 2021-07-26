import * as cloudformation from '@silver886/aws-cloudformation';
import * as sdk from 'aws-sdk';
import {env} from 'process';
const S3_CLIENT = new sdk.S3();

async function s3GetNotification(account: string, bucketName: string): Promise<sdk.S3.NotificationConfiguration> {
    const data = await S3_CLIENT.getBucketNotificationConfiguration({
        /* eslint-disable @typescript-eslint/naming-convention */
        Bucket:              bucketName,
        ExpectedBucketOwner: account,
        /* eslint-enable @typescript-eslint/naming-convention */
    }).promise();
    // eslint-disable-next-line no-console
    console.log(`Get ${bucketName} queue notification: ${(data.QueueConfigurations ?? 'unknown').toString()}`);

    // eslint-disable-next-line no-console
    if (!data.QueueConfigurations) console.error(`${bucketName} queue notification is undefined or empty.`);

    return data;
}

async function s3PutNotification(account: string, bucketName: string, config: sdk.S3.NotificationConfiguration): Promise<void> {
    // eslint-disable-next-line no-console
    console.log(`Put ${bucketName} queue notification: ${JSON.stringify(config)}`);
    await S3_CLIENT.putBucketNotificationConfiguration({
        /* eslint-disable @typescript-eslint/naming-convention */
        Bucket:                    bucketName,
        ExpectedBucketOwner:       account,
        NotificationConfiguration: config,
        /* eslint-enable @typescript-eslint/naming-convention */
    }).promise();
}

function idFilter(id: string): (v: sdk.S3.QueueConfiguration) => boolean {
    return (v: sdk.S3.QueueConfiguration): boolean => {
        if (v.Id) return v.Id !== id;
        return true;
    };
}

// eslint-disable-next-line max-lines-per-function, max-statements
export async function handler(event: cloudformation.CustomResource.Request.Event, context: unknown): Promise<void> {
    const resource = new cloudformation.CustomResource.Handle(event, event.LogicalResourceId);
    const logName = context as {logGroupName: string; logStreamName: string};
    resource.reason = `See the details in CloudWatch Log Group Stream: ${logName.logGroupName} ${logName.logStreamName}`;

    if (!env.sqsArn) throw new Error('No SQS Queue ARN provided.');

    if (!event.ResourceProperties) {
        await resource.failed('No property provided.');
        return;
    }
    if (typeof event.ResourceProperties.account !== 'string') {
        await resource.failed('No AWS Account provided.');
        return;
    }
    if (typeof event.ResourceProperties.s3Name !== 'string') {
        await resource.failed('No S3 Bucket Name provided.');
        return;
    }

    const s3GetNotifications: Array<Promise<sdk.S3.NotificationConfiguration>> = [
        s3GetNotification(event.ResourceProperties.account, event.ResourceProperties.s3Name),
    ];

    const newNotification: sdk.S3.QueueConfiguration = {
        /* eslint-disable @typescript-eslint/naming-convention */
        Id:     event.LogicalResourceId,
        Events: [
            's3:ObjectCreated:*',
        ],
        QueueArn: env.sqsArn,
        /* eslint-enable @typescript-eslint/naming-convention */
    };

    let [oldAccount, oldS3Name] = ['', ''];
    if (event.RequestType === cloudformation.CustomResource.Request.Type.UPDATE) {
        if (!event.OldResourceProperties) {
            await resource.failed('No old property provided.');
            return;
        }
        if (typeof event.OldResourceProperties.account !== 'string') {
            await resource.failed('No old AWS Account provided.');
            return;
        }
        if (typeof event.OldResourceProperties.s3Name !== 'string') {
            await resource.failed('No old KMS Key ID provided.');
            return;
        }
        oldS3Name = event.OldResourceProperties.s3Name;
        oldAccount = event.OldResourceProperties.account;
        if (oldS3Name !== event.ResourceProperties.s3Name) s3GetNotifications.push(s3GetNotification(oldAccount, oldS3Name));
    }

    try {
        const [notification, notificationOld] = await Promise.all(s3GetNotifications);
        switch (event.RequestType) {
            case cloudformation.CustomResource.Request.Type.CREATE:
                if (notification.QueueConfigurations) {
                    notification.QueueConfigurations.push(newNotification);
                } else {
                    notification.QueueConfigurations = [newNotification];
                }
                break;
            case cloudformation.CustomResource.Request.Type.DELETE:
                if (notification.QueueConfigurations?.length) {
                    notification.QueueConfigurations = notification.QueueConfigurations.
                        filter(idFilter(event.LogicalResourceId));
                }
                break;
            case cloudformation.CustomResource.Request.Type.UPDATE:
                if (notificationOld.QueueConfigurations?.length) {
                    notificationOld.QueueConfigurations = notificationOld.QueueConfigurations.
                        filter(idFilter(event.LogicalResourceId));
                }
                if (notification.QueueConfigurations) {
                    notification.QueueConfigurations.push(newNotification);
                } else {
                    notification.QueueConfigurations = [newNotification];
                }
                break;

            // No default
        }

        const s3PutNotifications: Array<Promise<void>> = [
            s3PutNotification(event.ResourceProperties.account, event.ResourceProperties.s3Name, notification),
        ];
        if (oldS3Name) s3PutNotifications.push(s3PutNotification(oldAccount, oldS3Name, notificationOld));

        await Promise.all(s3PutNotifications);

        await resource.success();
    } catch (err) {
        // eslint-disable-next-line no-console
        console.log('Error: ', err);
        await resource.failed('Cannot update S3 Bucket notification configuration.');
    }
}
