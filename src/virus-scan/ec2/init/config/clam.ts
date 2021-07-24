import * as ec2 from '@aws-cdk/aws-ec2';

import * as file from '../file/';

export function service(config: file.clam.Config): ec2.InitConfig {
    const handle = new ec2.InitServiceRestartHandle();
    return new ec2.InitConfig([
        ec2.InitPackage.yum('clamd'),
        ec2.InitPackage.yum('clamav'),
        ec2.InitPackage.yum('clamav-update'),
        ec2.InitPackage.yum('ruby'),
        ec2.InitPackage.rubyGem('aws-sdk-sqs', {
            version: ['1.23.1'],
        }),
        ec2.InitPackage.rubyGem('aws-sdk-sns', {
            version: ['1.20.0'],
        }),
        ec2.InitPackage.rubyGem('aws-sdk-s3', {
            version: ['1.54.0'],
        }),
        ec2.InitPackage.rubyGem('daemons', {
            version: ['1.3.1'],
        }),
        ec2.InitPackage.rubyGem('rubysl-securerandom', {
            version: ['2.0.0'],
        }),
        file.clam.daemon([handle]),
        file.clam.worker([handle]),
        file.clam.config(config, [handle]),
        file.clam.service([handle]),
        ec2.InitCommand.shellCommand('sed -i "s/^FRESHCLAM_DELAY/#FRESHCLAM_DELAY/g" /etc/sysconfig/freshclam'),
        ec2.InitCommand.shellCommand('sed -i "s/^Example/#Example/g" /etc/freshclam.conf'),
        ec2.InitCommand.shellCommand('mkdir /var/run/clamd.scan && chown clamscan:clamscan /var/run/clamd.scan', {
            testCmd: '[ ! -d /var/run/clamd.scan ]',
        }),
        ec2.InitCommand.shellCommand('sed -i "s/^Example/#Example/g;s/^#LocalSocket /LocalSocket /g" /etc/clamd.d/scan.conf'),
        ec2.InitCommand.shellCommand('ln -s /etc/clamd.d/scan.conf /etc/clamd.conf', {
            testCmd: '[ ! -f /etc/clamd.conf ]',
        }),
        ec2.InitCommand.shellCommand('freshclam'),
        ec2.InitCommand.shellCommand('systemctl enable clamd@scan', {
            testCmd: '! systemctl is-enabled clamd@scan',
        }),
        ec2.InitCommand.shellCommand('systemctl start clamd@scan', {
            testCmd: '! systemctl is-active clamd@scan',
        }),
        ec2.InitService.enable('s3-virus-scan', {
            serviceRestartHandle: handle,
        }),
    ]);
}
