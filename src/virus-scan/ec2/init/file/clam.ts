import {
    aws_ec2 as cdkEc2,
} from 'aws-cdk-lib';

export function daemon(serviceRestartHandles?: cdkEc2.InitServiceRestartHandle[]): cdkEc2.InitFile {
    return cdkEc2.InitFile.fromString('/opt/aws-s3-virus-scan/daemon.rb', '' +
        '#!/usr/bin/env ruby\n' +
        'require \'daemons\'\n' +
        'Daemons.run(__dir__ + \'/worker.rb\', {:app_name => \'s3-virus-scan\', :monitor => true, :dir_mode => :system, :log_output_syslog => true})', {
        mode: '000744',
        serviceRestartHandles,
    });
}

// eslint-disable-next-line max-lines-per-function
export function worker(serviceRestartHandles?: cdkEc2.InitServiceRestartHandle[]): cdkEc2.InitFile {
    return cdkEc2.InitFile.fromString('/opt/aws-s3-virus-scan/worker.rb', '' +
        '#!/usr/bin/env ruby\n' +
        'require \'aws-sdk-sqs\'\n' +
        'require \'aws-sdk-sns\'\n' +
        'require \'aws-sdk-s3\'\n' +
        'require \'json\'\n' +
        'require \'uri\'\n' +
        'require \'yaml\'\n' +
        'require \'syslog/logger\'\n' +
        'require \'securerandom\'\n' +
        '\n' +
        '$log = Syslog::Logger.new \'s3-virus-scan\'\n' +
        '\n' +
        'class Worker\n' +
        '\n' +
        '  attr_reader :conf, :sns, :s3, :tag_key\n' +
        '\n' +
        '  NO_STATUS = \'no\'\n' +
        '  CLEAN_STATUS = \'clean\'\n' +
        '  INFECTED_STATUS = \'infected\'\n' +
        '\n' +
        '  NO_ACTION = \'no\'\n' +
        '  TAG_ACTION = \'tag\'\n' +
        '  DELETE_ACTION = \'delete\'\n' +
        '\n' +
        '  def initialize\n' +
        '    @conf = YAML::load_file(__dir__ + \'/s3-virus-scan.conf\')\n' +
        '    Aws.config.update(region: conf[\'region\'])\n' +
        '    @tag_key = conf[\'tag_key\']\n' +
        '    @sns = Aws::SNS::Client.new()\n' +
        '    @s3 = Aws::S3::Client.new()\n' +
        '  end\n' +
        '\n' +
        '  def run\n' +
        '    $log.info "s3-virus-scan started"\n' +
        '\n' +
        '    poller = Aws::SQS::QueuePoller.new(conf[\'queue\'])\n' +
        '\n' +
        '    max_size = conf[\'volume_size\'] * 1073741824 / 2 # in bytes\n' +
        '\n' +
        '    poller.poll do |msg|\n' +
        '      begin\n' +
        '        body = JSON.parse(msg.body)\n' +
        '        $log.debug "body #{body}"\n' +
        '        if body.key?(\'Records\')\n' +
        '          body[\'Records\'].each do |record|\n' +
        '            bucket = record[\'s3\'][\'bucket\'][\'name\']\n' +
        '            key = URI.decode_www_form_component(record[\'s3\'][\'object\'][\'key\'])\n' +
        '            version = record[\'s3\'][\'object\'][\'versionId\']\n' +
        '            fileName = "/tmp/#{SecureRandom.uuid}"\n' +
        '            if record[\'s3\'][\'object\'][\'size\'] > max_size\n' +
        '              $log.info "s3://#{bucket}/#{key} #{version} bigger than half of the EBS volume, skip"\n' +
        '              if conf[\'tag_files\']\n' +
        '                tag(bucket, key, version, NO_STATUS);\n' +
        '              end\n' +
        '              publish_notification(bucket, key, version, NO_STATUS, NO_ACTION);\n' +
        '              next\n' +
        '            end\n' +
        '            $log.debug "downloading s3://#{bucket}/#{key} #{version}..."\n' +
        '            begin\n' +
        '              if version\n' +
        '                s3.get_object(\n' +
        '                  response_target: fileName,\n' +
        '                  bucket: bucket,\n' +
        '                  key: key,\n' +
        '                  version_id: version\n' +
        '                )\n' +
        '              else\n' +
        '                s3.get_object(\n' +
        '                  response_target: fileName,\n' +
        '                  bucket: bucket,\n' +
        '                  key: key\n' +
        '                )\n' +
        '              end\n' +
        '            rescue Aws::S3::Errors::NoSuchKey\n' +
        '              $log.info "s3://#{bucket}/#{key} #{version} does no longer exist, skip"\n' +
        '              next\n' +
        '            end\n' +
        '            begin\n' +
        '              $log.info "scanning s3://#{bucket}/#{key} #{version}..."\n' +
        '              system("clamdscan #{fileName}")\n' +
        '              exitstatus = $?.exitstatus\n' +
        '              if exitstatus == 0 # No virus found.\n' +
        '                if conf[\'tag_files\']\n' +
        '                  $log.debug "s3://#{bucket}/#{key} #{version} is clean (tagging)"\n' +
        '                  tag(bucket, key, version, CLEAN_STATUS);\n' +
        '                else\n' +
        '                  $log.debug "s3://#{bucket}/#{key} #{version} is clean"\n' +
        '                end\n' +
        '                if conf[\'report_clean\']\n' +
        '                  publish_notification(bucket, key, version, CLEAN_STATUS, NO_ACTION);\n' +
        '                end\n' +
        '              elsif exitstatus == 1 # Virus(es) found.\n' +
        '                if conf[\'delete\']\n' +
        '                  $log.debug "s3://#{bucket}/#{key} #{version} is infected (deleting)"\n' +
        '                  s3.delete_object(\n' +
        '                    bucket: bucket,\n' +
        '                    key: key\n' +
        '                  )\n' +
        '                  publish_notification(bucket, key, version, INFECTED_STATUS, DELETE_ACTION);\n' +
        '                elsif conf[\'tag_files\']\n' +
        '                  $log.debug "s3://#{bucket}/#{key} #{version} is infected (tagging)"\n' +
        '                  tag(bucket, key, version, INFECTED_STATUS);\n' +
        '                  publish_notification(bucket, key, version, INFECTED_STATUS, TAG_ACTION);\n' +
        '                else\n' +
        '                  $log.debug "s3://#{bucket}/#{key} #{version} is infected"\n' +
        '                  publish_notification(bucket, key, version, INFECTED_STATUS, NO_ACTION);\n' +
        '                end\n' +
        '              else # An error occurred.\n' +
        '                raise "s3://#{bucket}/#{key} #{version} could not be scanned, clamdscan exit status was #{exitstatus}, retry"\n' +
        '              end\n' +
        '            ensure\n' +
        '              system("rm #{fileName}")\n' +
        '            end\n' +
        '          end\n' +
        '        end\n' +
        '      rescue Exception => e\n' +
        '        $log.error "message failed: #{e.inspect} #{msg.inspect}"\n' +
        '        raise e\n' +
        '      end\n' +
        '    end\n' +
        '  end\n' +
        '\n' +
        '  private\n' +
        '\n' +
        '  def tag(bucket, key, version, status)\n' +
        '    if version\n' +
        '      s3.put_object_tagging(\n' +
        '        bucket: bucket,\n' +
        '        key: key,\n' +
        '        version_id: version,\n' +
        '        tagging: {tag_set: [{key: tag_key, value: status}]}\n' +
        '      )\n' +
        '    else\n' +
        '      s3.put_object_tagging(\n' +
        '        bucket: bucket,\n' +
        '        key: key,\n' +
        '        tagging: {tag_set: [{key: tag_key, value: status}]}\n' +
        '      )\n' +
        '    end\n' +
        '  end\n' +
        '\n' +
        '  def publish_notification(bucket, key, version, status, action)\n' +
        '    message_attributes = {\n' +
        '      "bucket" => {\n' +
        '        data_type: "String",\n' +
        '        string_value: bucket\n' +
        '      },\n' +
        '      "key" => {\n' +
        '        data_type: "String",\n' +
        '        string_value: key\n' +
        '      },\n' +
        '      "status" => {\n' +
        '        data_type: "String",\n' +
        '        string_value: status\n' +
        '      },\n' +
        '      "action" => {\n' +
        '        data_type: "String",\n' +
        '        string_value: action\n' +
        '      }\n' +
        '    }\n' +
        '    if version\n' +
        '      message_attributes[:version] = {\n' +
        '        data_type: "String",\n' +
        '        string_value: version\n' +
        '      }\n' +
        '    end\n' +
        '    sns.publish(\n' +
        '      topic_arn: conf[\'topic\'],\n' +
        '      message: "s3://#{bucket}/#{key} #{version} is #{status}, #{action} action executed",\n' +
        '      subject: "s3-virus-scan s3://#{bucket}",\n' +
        '      message_attributes: message_attributes\n' +
        '    )\n' +
        '  end\n' +
        '\n' +
        'end\n' +
        '\n' +
        'begin\n' +
        '  Worker.new.run\n' +
        'rescue Exception => e\n' +
        '  $log.error "worker failed: #{e.inspect}"\n' +
        '  raise e\n' +
        'end', {
        mode: '000744',
        serviceRestartHandles,
    });
}

export interface Config {
    deleteInfected: boolean;
    reportClean: boolean;
    tagKey?: string;
    region: string;
    queueUrl: string;
    topicArn: string;
    volumeSize: number;
}

export function config(cfg: Config, serviceRestartHandles?: cdkEc2.InitServiceRestartHandle[]): cdkEc2.InitFile {
    return cdkEc2.InitFile.fromString('/opt/aws-s3-virus-scan/s3-virus-scan.conf', '' +
        `delete: ${cfg.deleteInfected ? 'true' : 'false'}\n` +
        `report_clean: ${cfg.reportClean ? 'true' : 'false'}\n` +
        `tag_files: ${cfg.tagKey ? 'true' : 'false'}\n` +
        `tag_key: ${cfg.tagKey ?? ''}\n` +
        `region: ${cfg.region}\n` +
        `queue: ${cfg.queueUrl}\n` +
        `topic: ${cfg.topicArn}\n` +
        `volume_size: ${cfg.volumeSize}`, {
        serviceRestartHandles,
    });
}

export function service(serviceRestartHandles?: cdkEc2.InitServiceRestartHandle[]): cdkEc2.InitFile {
    return cdkEc2.InitFile.fromString('/etc/init.d/s3-virus-scan', '' +
        '#!/usr/bin/env ruby\n' +
        '# chkconfig:    - 80 20\n' +
        'APP_NAME = \'s3-virus-scan\'\n' +
        'APP_PATH = \'/opt/aws-s3-virus-scan/daemon.rb\'\n' +
        'case ARGV.first\n' +
        '  when \'start\'\n' +
        '    puts "Starting #{APP_NAME}..."\n' +
        '    system(APP_PATH, \'start\')\n' +
        '    exit($?.exitstatus)\n' +
        '  when \'stop\'\n' +
        '    system(APP_PATH, \'stop\')\n' +
        '    exit($?.exitstatus)\n' +
        '  when \'restart\'\n' +
        '    system(APP_PATH, \'restart\')\n' +
        '    exit($?.exitstatus)\n' +
        '  when \'status\'\n' +
        '    system(APP_PATH, \'status\')\n' +
        '    exit($?.exitstatus)\n' +
        'end\n' +
        'unless %w{start stop restart status}.include? ARGV.first\n' +
        '  puts "Usage: #{APP_NAME} {start|stop|restart|status}"\n' +
        '  exit(1)\n' +
        'end', {
        mode: '000755',
        serviceRestartHandles,
    });
}
