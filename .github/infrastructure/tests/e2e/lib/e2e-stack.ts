import * as cdk from "@aws-cdk/core"
import * as ec2 from "@aws-cdk/aws-ec2"

export class E2EStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const userData = ec2.UserData.forLinux()
    userData.addCommands(
      'apt-get update -y',
      'apt-get install -y git ca-certificates curl gnupg lsb-release jq',
      'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg',
      "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      'apt-get update -y',
      'apt-get install -y docker-ce docker-ce-cli containerd.io',
      'sudo usermod -aG docker ubuntu',
      "sudo curl -L \"https://github.com/docker/compose/releases/download/1.26.0/docker-compose-$(uname -s)-$(uname -m)\"  -o /usr/local/bin/docker-compose",
      "sudo mv /usr/local/bin/docker-compose /usr/bin/docker-compose",
      "sudo chmod +x /usr/bin/docker-compose",
      "wget -q https://go.dev/dl/go1.16.15.linux-amd64.tar.gz",
      "sudo tar -C /usr/local -xzf go1.16.15.linux-amd64.tar.gz",
      `echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile.d/go.sh > /dev/null`,
      `echo 'export PATH=$PATH:/home/ubuntu/go/bin' | sudo tee -a /etc/profile.d/go.sh > /dev/null`,
      "touch /tmp/finished-user-data",
    )

    const defaultVPC = ec2.Vpc.fromLookup(this, 'VPC', { isDefault: true });
    const subnetSelection = defaultVPC.selectSubnets({ subnetType: ec2.SubnetType.PUBLIC })

    const securityGroup = new ec2.SecurityGroup(this, 'EC2Instance-sg', {
      vpc: defaultVPC,
      allowAllOutbound: true, // will let your instance send outboud traffic
      securityGroupName: 'EC2Instance',
    })

    securityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(22),
      'Allows SSH access from Internet'
    )

    const rootVolume: ec2.BlockDevice = {
      deviceName: '/dev/sda1', // Use the root device name from Step 1
      volume: ec2.BlockDeviceVolume.ebs(50), // Override the volume size in Gibibytes (GiB)
    };

    const instance = new ec2.Instance(this, 'EC2Instance', {
      vpc: defaultVPC,
      vpcSubnets: subnetSelection,
      securityGroup: securityGroup,
      machineImage: ec2.MachineImage.genericLinux({
        "eu-west-1": "ami-00e7df8df28dfa791" //Ubuntu Server 20.04 LTS
      }),
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.T2,
        ec2.InstanceSize.LARGE
      ),
      keyName: "lamassu-githubactions",
      userData: userData,
      blockDevices: [
        rootVolume
      ]
    });

    cdk.Tags.of(instance).add('Name', 'lamassuGHActionsE2ETest');

    new cdk.CfnOutput(this, 'EC2Instance-subnet-output', {
      value: instance.instance.subnetId ? instance.instance.subnetId : "none"
    })

    new cdk.CfnOutput(this, 'EC2Instance-output', {
      value: instance.instancePublicIp
    })
  }
}
