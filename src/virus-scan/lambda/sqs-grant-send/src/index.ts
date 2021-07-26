import type * as Json from '@silver886/type-json';
import * as cloudformation from '@silver886/aws-cloudformation';
import * as sdk from 'aws-sdk';
import {env} from 'process';
const SQS_CLIENT = new sdk.SQS();

async function sqsGetQueuePolicy(queueUrl: string): Promise<Json.Object> {
    const data = await SQS_CLIENT.getQueueAttributes({
        /* eslint-disable @typescript-eslint/naming-convention */
        QueueUrl:       queueUrl,
        AttributeNames: ['Policy'],
        /* eslint-enable @typescript-eslint/naming-convention */
    }).promise();
    // eslint-disable-next-line no-console
    console.log(`Get ${queueUrl} policy: ${data.Attributes?.Policy ?? 'unknown'}`);

    if (!data.Attributes?.Policy) throw new Error(`${queueUrl} policy is undefined or empty.`);

    return JSON.parse(data.Attributes.Policy) as Json.Object;
}

async function sqsPutQueuePolicy(queueUrl: string, policy: Json.Object): Promise<void> {
    const policyString = JSON.stringify(policy);
    // eslint-disable-next-line no-console
    console.log(`Put ${queueUrl} policy: ${policyString}`);
    await SQS_CLIENT.setQueueAttributes({
        /* eslint-disable @typescript-eslint/naming-convention */
        QueueUrl:   queueUrl,
        Attributes: {
            Policy: policyString,
        },
        /* eslint-enable @typescript-eslint/naming-convention */
    }).promise();
}

function sidFilter(sid: string): (v: Json.Value) => boolean {
    return (v: Json.Value): boolean => {
        const s = v as Json.Object;

        if (typeof s.Sid === 'string') return s.Sid !== sid;

        return true;
    };
}

// eslint-disable-next-line max-statements
export async function handler(event: cloudformation.CustomResource.Request.Event, context: unknown): Promise<void> {
    const resource = new cloudformation.CustomResource.Handle(event, event.LogicalResourceId);
    const logName = context as {logGroupName: string; logStreamName: string};
    resource.reason = `See the details in CloudWatch Log Group Stream: ${logName.logGroupName} ${logName.logStreamName}`;

    if (!env.sqsArn) throw new Error('No SQS Queue ARN provided.');
    if (!env.sqsUrl) throw new Error('No SQS Queue URL provided.');

    if (!event.ResourceProperties) {
        await resource.failed('No property provided.');
        return;
    }
    if (typeof event.ResourceProperties.account !== 'string') {
        await resource.failed('No AWS Account provided.');
        return;
    }
    if (typeof event.ResourceProperties.s3Arn !== 'string') {
        await resource.failed('No S3 Bucket ARN provided.');
        return;
    }

    const newPolicy: Json.Object = {
        /* eslint-disable @typescript-eslint/naming-convention */
        Sid:       event.LogicalResourceId,
        Effect:    'Allow',
        Principal: {
            Service: 's3.amazonaws.com',
        },
        Action:    'sqs:SendMessage',
        Resource:  env.sqsArn,
        Condition: {
            StringEquals: {
                'aws:SourceAccount': event.ResourceProperties.account,
            },
            ArnEquals: {
                'aws:SourceArn': event.ResourceProperties.s3Arn,
            },
        },
        /* eslint-enable @typescript-eslint/naming-convention */
    };

    try {
        const policy = await sqsGetQueuePolicy(env.sqsUrl);
        switch (event.RequestType) {
            case cloudformation.CustomResource.Request.Type.CREATE:
                (policy.Statement as Json.Array).push(newPolicy);
                break;
            case cloudformation.CustomResource.Request.Type.DELETE:
                policy.Statement = (policy.Statement as Json.Array).filter(sidFilter(event.LogicalResourceId));
                break;
            case cloudformation.CustomResource.Request.Type.UPDATE:
                policy.Statement = [
                    ...(policy.Statement as Json.Array).filter(sidFilter(event.LogicalResourceId)),
                    newPolicy,
                ];
                break;

            // No default
        }

        await sqsPutQueuePolicy(env.sqsUrl, policy);

        await resource.success();
    } catch (err) {
        // eslint-disable-next-line no-console
        console.log('Error: ', err);
        await resource.failed('Cannot update SQS Queue send message permission.');
    }
}
