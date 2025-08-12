# SOC Home Lab
Step-by-step guide to building your own Security Operations Center (SOC) home lab using pfSense, Wazuh, Suricata, TheHive, OpenCTI, and endpoint monitoring. Includes network diagrams, VM configuration details, installation commands, and integration workflows.

## Introduction
This project walks you through building a production-style SOC home lab on VMware Workstation Pro. You’ll deploy a routed two-LAN topology with pfSense (plus Suricata), a SIEM stack with Wazuh (manager/indexer/dashboard), incident response with TheHive, threat intel with OpenCTI, and Windows/Ubuntu endpoints instrumented with agents and Sysmon.

## ARCHITECTURE OVERVIEW
<img width="750" alt="image" src="https://github.com/user-attachments/assets/47e4821b-8f94-4e20-a9ab-70d8a5f35383" />

### **LAN 1 (SOC)** – `10.0.10.0/27`  
*Wazuh AIO, TheHive, Caldera, Shuffle, OpenCTI, SOC Analyst*

### **LAN 2 (Users)** – `10.0.20.0/24`  
*Windows 10, Ubuntu Desktop*

### **WAN** – `192.168.2.0/24`  
*Internet*

### **Before starting anything, I suggest you to always take snapshots in case something goes wrong.**


First thing first, we need to create the virtual networks on VMware Workstation Pro using virtual NICs, pfSense, and all the tools shown. To do that, we start by running Virtual Network Editor (as Administrator) and create 3 networks:
VMnet3 (LAN1) as Host-only (10.0.10.0/27), VMnet4 (LAN2) as Host-only (10.0.20.0/24) and VMnet8 (WAN) as NAT (192.168.2.0/24).
pfSense will handle IP assignments for both LANs so VMware’s built-in DHCP should be disabled.

<img width="750" alt="image" src="https://github.com/user-attachments/assets/cf7172fe-8b5f-4af0-a786-057661777602" />


After downloading pfSense ISO, we create a new VM with FreeBSD as the OS. Allocate the resources as you want, but do not forget that we will also have Suricata along with pfSense even though pfSense alone is lightweight.

On the virtual machine, 3 Network Adapters should be added:

- **NIC1** → VMnet8 (NAT) → `WAN`

- **NIC2** → VMnet3 → `LAN 1 (SOC)`

- **NIC3** → VMnet4 → `LAN 2 (Users)`

You're now ready to launch the virtual machine. For the installation, the installer will require a few information to be able to run. You will be asked what interface will be used for WAN (em0 since it’s the first NIC), and which interfaces will be used for LANs (em1, em2). For the em0 interface, just proceed with the installation without modifying anything. For the interface em1 and em2, you need to specify the network address in each (10.0.10.0/27 for LAN1 and 10.0.20.0/24 for LAN2).

The installer will prompt you to assign a WAN interface and LAN interface (not 2) at first. Assign the LAN interface to one of the two LANs you have. You will be able to assign the second LAN interface once the installation is complete.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/73080501-1364-4d96-9f66-761e60a3f177" />

We will configure the firewall and add Suricata.

We’ll now deploy our VMs for our SOC and our end-users networks.

To be able to configure the firewall via the Web GUI and allow any inbound and outbound connection for the moment, I’ll just deploy my SOC Analyst VM created with Ubuntu 22.04 Desktop and access the portal on 10.0.10.1. We should first disable the firewall temporarily to be able to go to the portal by choosing the option 8 (shell) and disabling it with the command pfctl -d.

After login in, you should into Firewall -> Rules -> (interface) & pass (allow) everything any <-> any to any protocol.

## Wazuh AIO (SIEM)
We’ll start with the Wazuh All-In-One. The solution is composed of a single universal agent and three central components: the Wazuh server, the Wazuh indexer, and the Wazuh dashboard.

We’re going to install the Wazuh central components on a single host first, and we’ll add Wazuh agents on our endpoints later, once everything is installed and configured properly. The documentation for the installation can be found on the official Wazuh's website.

Based on the installation guide, we’ll follow this installation workflow:

<img width="800" alt="image" src="https://github.com/user-attachments/assets/21493956-1400-4e17-9072-02d785ce1dbf" />

To start with the installation, we will first deploy our first VM **(10.0.10.2)** and will use Ubuntu 22.04 Server (as one of the operating systems recommended in the document) with 10GB RAM. The recommended resources allocations can also be found on the documentation, and 10GB RAM is not enough for a real scenario but we’ll go with that for our home lab.

### Wazuh Indexer
Based on the installation guide, we have to download the Wazuh installation assist and the configuration file. (PS: You need root user privileges to run all the commands described below.)
Afterwards, we need to edit the ./config.yml file and replace the node names and IP values with the corresponding names and IP addresses. We need to do this for all Wazuh server, Wazuh indexer, and Wazuh dashboard nodes. Since we’re using a single host (10.0.10.2), all node IPs in config.yml should point to 10.0.10.2.

<img width="484" height="569" alt="image" src="https://github.com/user-attachments/assets/79b528bb-8755-4067-874d-7572a029db4d" />

We are now ready to run the installation assist with the option --generate-config-files.

<img width="683" height="21" alt="image" src="https://github.com/user-attachments/assets/8f7d8ef9-b693-47c0-90bf-145f1768a588" />

The file generated (wazuh-install-files.tar) contains the Wazuh cluster key, certificates, and passwords necessary for installation.
Now that we have the necessities, we re-run the Wazuh installation assistant with the option --wazuh-indexer and the node name to install and configure the Wazuh indexer. (node-1 in our situation)

Make sure that the file generated is in the same directory.

Finally, we have to do the cluster initialization. We’re on a single-node deployment situation. To load the new certificates information and start the cluster, option --start-cluster will be used.

Once done, we’ll test the cluster installation. To get the admin password, we should run:
```bash
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1
```

Once we have the admin password, we test the credentials by running the following command to make sure that the installation has been successful.
```bash
curl -k -u admin:<ADMIN_PASSWORD> https://10.0.10.2:9200
```
<img width="659" height="321" alt="image" src="https://github.com/user-attachments/assets/bf471a08-5dc7-4960-ba2d-23b862169ead" />

To check if the cluster is working correctly:
```bash
curl -k -u admin:<ADMIN_PASSWORD> https://<WAZUH_INDEXER_IP>:9200/_cat/nodes?v
```
<img width="800" alt="image" src="https://github.com/user-attachments/assets/422655e7-b5a7-4f70-b08d-1d1db48f5e26" />



### Wazuh Server
The most complicated part is done. To complete the Wazuh server cluster installation, we only need to run the Wazuh installation assistant with the option --wazuh-server followed by the node name.
Wazuh Dashboard
We repeat the same command, followed by the option --wazuh-dashboard and the node name.

### Wazuh Dashboard 
We repeat the same command, followed by the option --wazuh-dashboard and the node name.


### Easier option for Wazuh central components on the same host

If we want to skip installing the central components one by one, we can run the Wazuh installation assistant and let it take care of the installation of all the components.
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

And we are in! The dashboard has been hosted on your_ip:443.

To change the password for the Wazuh indexer and Wazuh API user passwords, there’s passwords tools embedded in the Wazuh indexer under /usr/share/wazuh-indexer/plugins/opensearch-security/tools/.

(temporary pwd: /usr/share/wazuh-indexer/plugins/opensearch-security/tools/)

We will be back on configuring Wazuh once we deployed everything.

## TheHive (Case Management)
TheHive is a one case management platform for all SOCs, CERTs & CSIRTs. This is where alert will be sent.
Following their documentation, the hardware requirements for < 10 users are:
<img width="800" alt="image" src="https://github.com/user-attachments/assets/6f9ffd3e-bc63-4587-be9e-e963b3fc9d21" />

There’re many recommended operating systems but I’ll continue using Ubuntu 22.04.

We can install TheHive step-by-step but the processus will take time because there’s many things to install and configure so we will go with the installation script. We need to execute the following script:
```bash
wget -q -O /tmp/install_script.sh https://scripts.download.strangebee.com/latest/sh/install_script.sh ; sudo -v ; bash /tmp/install_script.sh
```
Once we run the script, we are prompted to choose what we want to install.
<img width="646" height="128" alt="image" src="https://github.com/user-attachments/assets/fee5a2d8-599c-4009-bd8f-1b2dd92d9129" />

We will just install TheHive for now. The option 2 will deploy TheHive along with its dependencies.
<img width="628" height="190" alt="image" src="https://github.com/user-attachments/assets/2eb690c5-ad73-4387-ab20-b761776f50f9" />

I had a problem with the script when it was time to install TheHive, so I did it manually.

First of all, I installed TheHive 5.2 and to do that, I had to install the package along with the SHA256 checksum and signature files.

To do that, for the package we run the command:
```bash
wget -O /tmp/thehive_5.2.4-1_all.deb https://thehive.download.strangebee.com/5.2/deb/thehive_5.2.4-1_all.deb
```
For the signature files:
```bash
wget -O /tmp/thehive_5.2.4-1_all.deb.asc
```

Second of all, we have to verify the GPG signature using the public key.
```bash
wget -O /tmp/strangebee.gpg https://keys.download.strangebee.com/latest/gpg/strangebee.gpg
```
We import the key into the GPG keyring.

To verify the downloaded package signature, we use:
```bash
gpg --verify /tmp/thehive_5.2.4-1_all.deb.asc verify /tmp/thehive_5.2.4-1_all.deb
```
<img width="895" height="198" alt="image" src="https://github.com/user-attachments/assets/46ae6425-0e0b-4324-80f2-44d1d7e42caf" />


And finally, we install the package by using apt. 
```bash
sudo apt-get install /tmp/thehive_5.2.4-1_all.deb
```

To successfully initiate TheHive, we need to configurate the secret key configuration, the database configuration and the file storage configuration. Since we used .deb, the secret key is automatically generated and stored in /etc/thehive/secret.conf during package installation.

For the home lab, we will leave everything as default but in real case scenarios, we’ll have to authenticate Apache Cassandra and Elasticsearch and modify the File Storage (Local Filesystem or S3). Everything is well document on the StrangeBee’s (TheHive's creators) website. If you want to modify of all that, you can access the configuration file in /etc/thehive/application.conf.

Time to run it! To start TheHive service and enable it to run on system boot, we have to start and enable on boot Cassandra and Elasticsearch too.
```bash
sudo systemctl start cassandra ; sudo systemctl enable cassandra
sudo systemctl start elasticsearch ; sudo systemctl enable elasticsearch
sudo systemctl start thehive ; sudo systemctl enable thehive
```
Elasticsearch started and failed after. After checking the journalctl, I saw that OOM killer killed the process. That means that it’s out of memory. To fix that, we need to adjust the heap. Currently, based on the file /etc/elasticsearch/jvm.options.d/heap.options, Elasticsearch is requesting 4Gb. Since we are limited on resources, we’ll lower it to 1Gb.

<img width="426" height="60" alt="image" src="https://github.com/user-attachments/assets/d9935472-fa5a-4629-9ed1-94802f82fdc3" />

And on the port 9000…

<img width="800" alt="image" src="https://github.com/user-attachments/assets/73f5a063-ad43-4e58-9b35-60ba2e040f7c" />

Here we are! The default admin user credentials are admin@thehive.local:secret.

## OpenCTI (you can skip for later if not needed)
OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables. It has been created in order to structure, store, organize and visualize technical and non-technical information about cyber threats.
We will configure it primarily to use the  (through a ) to help structure the data and to gather IoCs.

Since we are doing it on a Ubuntu VM, we will proceed with a manual installation instead of using Docker. Docker Desktop for Linux utilizes a lightweight Virtual Machine (VM) to run containers, and we can have conflict for virtualization on a virtual machine (depending on the hypervisor and the host system) so we will not be having nested virtualization.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/82bbba85-2997-4742-9ef2-c5a4d351637a" />

Based on this architecture, we have to install Elasticsearch for the database, redis for events stream, a S3 bucket for storage, and RabbitMQ for Messaging system, along with the needed dependencies for the main application and the workers.

### Installing Elasticsearch
First, before installing Elasticsearch, we have to import the Elasticsearch PGP key.
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

<img width="621" height="384" alt="image" src="https://github.com/user-attachments/assets/7b6c2d95-1a55-43cc-9a06-fed8e10ca321" />

The versions should be respected.
We will install Elasticsearch using the APT repository. We may need to install the apt-transport-https package first:
```bash
sudo apt-get install apt-transport-https
```
We then save the repo definition to /etc/apt/sources.list.d/elastic-9.x.list:
```bash
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```
And finally, we install the Elasticsearch Debian package:
```bash
sudo apt-get update && sudo apt-get install elasticsearch
```
Since Elasticsearch is on the same host, we don’t need to configure it for now for nodes for example. We will just make it start automatically when the system boots up with systemd.
```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
```
Then we start the elasticsearch.service:
```bash
sudo systemctl start elasticsearch.service
```
We reset the elastic superuser password using the reset password tool. The path is /usr/share/elasticsearch/ and we use the tool with bin/elasticsearch-reset-password -u elastic.

To make sure that it’s working, we can curl the URL.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/2e55c917-8f97-4cec-93db-cf2321cfb7ff" />



### Installing RabbitMQ
First: 
```bash
sudo apt-get install curl gnupg apt-transport-https -y
```

We then import RabbitMQ’s signing key.
```bash
curl -1sLf "https://keys.openpgp.org/vks/v1/by-fingerprint/0A9AF2115F4687BD29803A206B73A36E6026DFCA" | sudo gpg --dearmor | sudo tee /usr/share/keyrings/com.rabbitmq.team.gpg > /dev/null
```

We’ll have to add Erlang and RabbitMQ packages.
```bash
sudo tee /etc/apt/sources.list.d/rabbitmq.list <<EOF
```

---

Modern Erlang/OTP releases
```bash
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb1.rabbitmq.com/rabbitmq-erlang/ubuntu/jammy jammy main
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb2.rabbitmq.com/rabbitmq-erlang/ubuntu/jammy jammy main
```

---

Latest RabbitMQ releases
```bash
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb1.rabbitmq.com/rabbitmq-server/ubuntu/jammy jammy main
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb2.rabbitmq.com/rabbitmq-server/ubuntu/jammy jammy main
sudo apt-get update -y
```

We can see the available versions in the APT repo by doing apt list -a rabbitmq-server.

Before installing the RabbitMQ server, we need to install Erlang so the installation works.
```bash
sudo apt-get install -y erlang-base \
erlang-asn1 erlang-crypto erlang-eldap erlang-ftp erlang-inets \
erlang-mnesia erlang-os-mon erlang-parsetools erlang-public-key \
erlang-runtime-tools erlang-snmp erlang-ssl \
erlang-syntax-tools erlang-tftp erlang-tools erlang-xmerl
```

Once installed, we install our RabbitMQ server.
```bash
sudo apt-get install rabbitmq-server-y –fix-missing
```

Perfect. The installation of RabbitMQ is complete. We run it using the systemctl start rabbitmq-server command. I’ll also enable it to start when the system boots up.

The broker creates a user guest with password guest. These credentials can only be used when connecting to the broker as localhost.

### MinIO
MinIO is a self-hosted S3-compatible object storage. The installation is pretty easy. We download the folder following the official GitHub recommendation:
```bash
wget https://dl.min.io/server/minio/release/linux-amd64/minio
```

We give it an additional execute privilege. 
```bash
chmod +x minio
```
Then, we run: *./minio server /data*

<img width="800" alt="image" src="https://github.com/user-attachments/assets/7bbffeb7-8d3e-445c-a348-1cb7283f7119" />

Once the server is up, we login on the WebUI to create a bucket named opencti-bucket.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/54af94c6-e9f4-440b-8b92-19837f409b40" />


### Redis
We will install Redis based on this documentation: https://github.com/redis/redis-debian
```bash
sudo apt-get update
sudo apt-get install lsb-release curl gpg
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
sudo chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt-get update
sudo apt-get install redis
```


### OpenCTI 
To begin, we have to install all the needed dependencies for the main application and the workers, since the OpenCTI platform relies on several external databases and services in order to work.
```bash
sudo apt-get update
sudo apt-get install build-essential nodejs npm python3 python3-pip python3-dev
```
Once we have the needed dependencies installed, we have to download and extract the latest release file from the OpenCTI’s project on GitHub: https://github.com/OpenCTI-Platform/opencti/releases]

Since we are on Ubuntu, we have to install the opencti-release_{RELEASE_VERSION}.tar.gz version. Right now, the latest version available for me is the version 6.7.9.

Once we installed the latest version, we have to decompress it. Based on the extensions .tar and .gz, it tells us that tar collected all the files into one package, and gzip was used to compress it.

To decompress it, we use tar -xvzf opencti-release-6.7.9.tar.gz. (**f** must be the last flag.  It tells tar the name and path of the compressed file; **z** tells tar to decompress the archive using gzip; **x** collects files or extract them. **V** is for Verbose output to show you all the files being extracted)

### Installing the main platform

We’ll configure the application. The main application has one JSON configuration file and some Python modules to install.

<img width="535" height="41" alt="image" src="https://github.com/user-attachments/assets/a58425cd-7215-41d5-afee-9413b5698e0d" />

We will create a new .json file (production.json) and edit it to make all the servers we just installed to work between them.
cp config/default.json config/production.json

Since all of our servers are on default configuration, we don’t really need to touch the configuration file except for the MinIO part. Along with the given port, we have to input the username and password of the API that is visible on :9000.

<img width="553" height="271" alt="image" src="https://github.com/user-attachments/assets/772f3d0d-b4fd-4440-a8a8-2b51a25b7deb" />


We’re going to install the Python modules. To do that, we go to */src/python* and using pip3, we install the modules:
```bash
pip3 install -r requirements.txt
```

We have to make sure that yarn version > 4 (yarn –version) and the node version is >= 19 because the application is just a NodeJS process. In my case, none of them are. To install yarn:
```bash
npm install --global yarn
```
The Node.js version is the linux package manager is outdated to so we have to install it from the official website, https://nodejs.org/en/download.

Once it’s done and Node.js is setup, we build and run within the opencti folder:

```bash
yarn install
yarn build
yarn serv
```

## Deploying the end-users
We deployed all of our servers and now we need to deploy our end-users. These will be the devices that will generate the most traffic. We will be able to conduct tests on them to write detection rules. The detection rules will mostly be created for our IDS/IPS (Suricata) and for our SIEM, on Wazuh.

Our end-users will be on LAN2 (10.0.20.0/24).

First of all, we will need to deploy two VMs of different OS, one with Windows and one with Ubuntu. I will skip this part and let you do it. Do not forget to connect them to the LAN we created with the Virtual Network Editor.

Remember the diagram? Each one of our VMs had an IP address. Even though we activated a DHCP server on both of our LANs, it is possible to keep each IP address assigned to our machines. This functionality is called DHCP Static Mapping, and it is possible to do it on the pfSense web interface. All you have to do is to specify the MAC address of your interface and a hostname.

- LAN1:
  
  <img width="800" alt="image" src="https://github.com/user-attachments/assets/1cc2ade9-265c-446b-baad-0e8e38cd314a" />


- LAN2:

  <img width="800" alt="image" src="https://github.com/user-attachments/assets/acd70b55-db8f-42f5-8f83-3b3fe193195d" />



Perfect. Now that our end-users VMs are deployed, we want to know what type of logs we want to send to the SIEM. But are we going to repeat the same process on each VM? Absolutely not. It’s a waste of time. That’s why automation tools exist. We will use **Ansible** to automate the configurations on all of our Ubuntu VMs and we will do it manually on the Windows machine since we only have one machine for now.

We will start with our Windows machine and proceed with Ansible afterwards.

### Configuring the Windows end-user
The first question we have to ask ourselves before we proceed is: what do we want to log and monitor from each of our endpoints?

The answer will depend on the situation. We are in a home lab so there’s not a lot of traffic, but in the real world, the organization can have thousands of endpoints depending on its size.

For my case, I will log the Windows Event Logs, Sysmon, and ClamAV.

Events logged in **Windows Event Logs** include application installations, security management, initial startup operations, and problems or errors. In the Windows Event Logs framework, we have **Windows Security Logs**. In the security events, we can find account log on, account management, directory service access, logon, object access (for example, file access), policy change, privilege use, tracking of system processes, system events.

Sysmon provides detailed information about process creations, network connections, and changes to file creation time. If you’re using Sysmon in a large organization, you have to tune it and only keep what you want because it can generate a lot of traffic.

### Sysmon Installation
We need to install the .zip found on Microsoft, in the Sysinternals tools. Once it’s installed, we unzip it then we go to the directory path with Windows Powershell (as Administrator). Like I said before, Sysmon can make noises and you may use a configuration file to decide what should be logged. For my home lab, I will go with the default settings.

Once in the path, all you need to do is to execute Sysmon with the parameter needed:

<img width="800" alt="image" src="https://github.com/user-attachments/assets/fc41156e-fd2e-48bc-bbe8-2b59f781c148" />

Sysmon logs now to the Windows Event Logs.

The events are stored in *Applications and Services Logs/Microsoft/Windows/Sysmon/Operational* in the Event Viewer.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/962186b0-d15f-4559-83a3-0dd803463c45" />


### Deploying a Wazuh agent for Windows
To be able to send the logs to the Wazuh server, we first need to install a Wazuh agent on our endpoint that will monitor and communicates with the Wazuh server, sending data in near real-time through an encrypted and authenticated channel.

The Wazuh agent for Windows is downloadable from here:

https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html


To start the installation process, we download the Windows installer.

With Powershell, we go to where we downloaded the .msi and we execute it with the given parameters:
```bash
.\wazuh-agent-4.12.0-1.msi /q WAZUH_MANAGER="10.0.10.2"
```

We start with the agent with *NET START WazuhSvc*.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/4673d0f9-8009-40d8-bdad-ea73af0dd123" />

And… on the Wazuh dashboard:

<img width="800" alt="image" src="https://github.com/user-attachments/assets/6aa33b2e-dd22-4c68-aa70-273b16767680" />


Good job!

All agent files are stored in C:\Program Files (x86)\ossec-agent after the installation.

There is one little problem: the Wazuh agent is not sending the logs from Sysmon for now. We have to add the function in the *ossec.conf* file.

Add these lines (PS: respect the format of the file):

```bash
<localfile>
<location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format>
</localfile>
```

After adding these lines, restart the agent with *NET STOP WazuhSvc* and *NET START WazuhSvc* again. 

To make sure that everything is working fine, we will go on our Wazuh web interface (10.0.10.2) and we will see if Sysmon logs are also sent to the SIEM.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/b4ac857b-6698-47d9-8552-8c03534b83cd" />

### Deploying Wazuh agent on Ubuntu via Ansible
We will use Ansible on our machine SOC Analyst. First of all, to be able to configure all the machines, they need to have SSH installed. You can simply download it doing *sudo apt update && sudo apt install ssh* on the Ubuntu machines.

The second thing to do is to generate a public/private RSA key pair on the SOC Analyst machine so we can use it afterwards to log in on other machines without entering the password each time. It is also more secure this way. You can even disable login by password once it is done.
To generate the keys we talked about, all we have to do is *ssh-keygen* and follow the instructions.

Now that we have our keys generated, we can copy our public key to the other machines with:

```bash
ssh-copy-id -i ~/.ssh/mykey user@host
```
This logs into the server host, and copies keys to the server, and configures them to grant access by adding them to the *authorized_keys* file.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/14fc6b59-51f0-4da4-beab-a2413318987a" />


For now, I will just install the Wazuh agents on three of my Ubuntu machines, because I’ll continue configuring the others a little more. The machines are the Ubuntu end-user and the SOC Analyst machine.

We need to install Ansible. To do that on Ubuntu, we simply use the following commands:
```bash
$ sudo apt update
$ sudo apt install software-properties-common
$ sudo add-apt-repository --yes --update ppa:ansible/ansible
$ sudo apt install ansible
```

Here’s how Ansible will work:

<img width="800" alt="image" src="https://github.com/user-attachments/assets/4585f10a-46c1-41b3-a803-c791ea6431a8" />

The control node is in the SOC Analyst machine.
Once ansible is installed, we make a directory. I’ll name it *ansible_quickstart*.
In this directory, we’ll create an inventory and name it *inventory.ini*.
You can see the documentation here to create inventories in your way:
I’ll keep it simple and create the inventory as follow:

<img width="660" height="90" alt="image" src="https://github.com/user-attachments/assets/9c4b28fe-28f3-45ed-8401-e2709adb27ed" />

**I did a stupid error by deploying an agent on the same host of the Wazuh server. Do not do that. It created conflict and I had to re-deploy the Wazuh server.**

That tells Ansible to connect to these users while using SSH (ansible_user) and use sudo (ansible_become).

Note that I will use the password for sudo in a single command after but all my passwords are the same (I know it’s not secure, it’s just to not forget every password for the home lab). In your case, you’ll have to see the Ansible documentation to see how you can give Ansible the password in a secure encrypted way or you can create a passwordless sudo account for all your VMs and use it for automation tasks via an authorized public key.

We will create our first playbook for testing if everything works fine.

Playbooks are automation blueprints, in YAML format, that Ansible uses to deploy and configure managed nodes.

<img width="714" height="291" alt="image" src="https://github.com/user-attachments/assets/0978277e-cb7b-4a4c-92fa-b250e523532e" />

It is important you respect the YAML syntax for the playbooks. You can find more details here:

https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html

You can also check the indexes of all modules and plugins here:

https://docs.ansible.com/ansible/latest/collections/all_plugins.html

Like I said before, I have the same password for all my accounts. Please refer here to know how to put a password for privilege escalation using Ansible:

https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html

<img width="800" alt="image" src="https://github.com/user-attachments/assets/6108a8e8-0ddc-4c19-acd0-e97fe2627943" />

<img width="800" alt="image" src="https://github.com/user-attachments/assets/db5778ee-8009-40bf-8d52-4ac80f364a34" />

Cool! We can now make our playbook to install the Wazuh agents on our machines so they send the useful logs directly to the SIEM.

We will also use the Wazuh documentation to deploy agents on a Linux operating system.

https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html

<img width="800" alt="image" src="https://github.com/user-attachments/assets/741130ed-100b-4e79-8fba-f44735a78a63" />

Basically, in this playbook, what we’re doing is simple. First, we will verify if curl and gnupg are present to be able to import the GPG key, then we are just following the documentation on the Wazuh official website to deploy the Wazuh agents.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/866945e8-958a-46a4-9f29-39396bbc0756" />

*(the error was because of a dpkg lock, I just had to terminate another apt)*

And… we have all of our agents sending logs to our SIEM!

<img width="800" alt="image" src="https://github.com/user-attachments/assets/2dfcae0b-f4cb-4a7b-8022-597afbc9a9f7" />

## Connecting TheHive and Wazuh
After login in to TheHive, we need to add an organization.

<img width="419" height="315" alt="image" src="https://github.com/user-attachments/assets/8667ab68-b7b3-4f6d-b9c6-1dae24db1c96" />

Second step: creating a new user with the organization administrator privileges.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/ba39eae0-96e5-4463-ab8c-da8fac12d098" />

We give it a new password to be able to log in, view the dashboard and manage cases.

The integration with Wazuh is possible with the aid of TheHive REST API. Therefore, we need a user on TheHive that can create alerts via the API. We create a new account with “analyst” privileges for this purpose.

Next, we generate a API key for the user.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/ba0c5856-71b0-4a79-947c-26d62b4efa63" />

We go on the Wazuh machine. We need to install TheHive Python module:
```bash
sudo /var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1
```

When it’s done, we create a custom integration script by pasting the python code that is available in this following documentation in /var/ossec/integrations/custom-w2thive.py:

https://wazuh.com/blog/using-wazuh-and-thehive-for-threat-protection-and-incident-response/

We create the bash script in the same documentation to run the .py.

Then we change both files’ permissions to 755 and owners too.

```bash
sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
sudo chmod 755 /var/ossec/integrations/custom-w2thive
sudo chown root:ossec /var/ossec/integrations/custom-w2thive.py
sudo chown root:ossec /var/ossec/integrations/custom-w2thive
```

For the final step, we have to edit the configuration file located at */var/ossec/etc/ossec.conf* and add the following lines along with your API key and your server’s IP:

```bash
<ossec_config>
…
<integration>
<name>custom-w2thive</name>
<hook_url>http://10.0.10.3:9000</hook_url>
<api_key>THE API KEY</api_key>
<alert_format>json</alert_format>
</integration>
…
</ossec_config>
```

After restarting the wazuh-manager and going into our “wazuh” account we created earlier, we can now see the alerts that are being generated. You can adjust the .py later to filter only the important alerts to go on TheHive.

## Installing Suricata on pfSense
pfSense made it pretty easy to integrate Suricata or any other available package to it. On your pfSense website dashboard, go to System -> Package Manager -> Available Packages and install Suricata. Once installed, you have to decide if you want to run Suricata in IDS mode or IPS inline mode. To run it in IDS mode, add to */etc/rc.conf*:
```bash
suricata_enable=”YES”
suricata_interface=”<interface>”
```

It is mandatory to declare the interface for Suricata in IDS Mode.
Alternatively, if you want to run Suricata in InLine IPS Mode in high-speed netmap mode, add to /etc/rc.conf:
```bash
suricata_enable=”YES”
suricata_netmap=”YES”
```

To learn more about how Suricata works, read their documentation and how you write rules.

It’s time to configure Suricata on pfSense. Go to Services -> Suricata and add an interface for Suricata. For myself, I will choose the interface of the end-users.

We now want to send our firewall and Suricata logs directly to Wazuh, and we'll achieve that by sending the logs to a Syslog server on Wazuh's machine.

Since we don’t want everything to be sent to our SIEM but only alerts based on our rules, we enable EVE JSON Log. For the output type, we choose SYSLOG.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/450b6fc0-def2-4d0e-9afc-b32897c9e761" />

Once done, we go to Status -> System Logs -> Settings and change the log message format to SYSLOG. Finally, in Remote Logging Options, we enable remote logging, choose the source address to the SOC’s network interface (10.0.10.1), and enter the remote syslog server: 10.0.10.2:514. I’ll just log firewall events for now.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/32a1a5d5-d58b-4c46-9ba3-849a6c50230e" />

We now need to configure Wazuh to listen to syslog messages on UDP port 514. To do that, go to */var/ossec/etc/ossec.conf*:

<img width="459" height="170" alt="image" src="https://github.com/user-attachments/assets/21a7cc17-806a-4867-bf49-8330c8424512" />

Restart Wazuh after doing so with *systemctl restart wazuh-manager*.

We will now try to fire a Suricata alert. Go to Services -> Suricata -> Interface Settings -> LAN – Rules and add a custom rule to identify an ICMP packet on 10.0.20.2 coming from anywhere.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/05e51b7d-6c6d-4fa3-9906-dfae9ae44147" />

Perfecto! We’ll try to ping our host with another machine and see if it triggers an alert.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/25b23d2e-69a0-4986-96af-c2e17c39ec8f" />

Bingo! I’ll let you integrate the alerts into the Wazuh dashboard. You’ll have to pass by a decoder. You can learn more on their official documentation.

## Final Thoughts
This SOC home lab provides a solid foundation for simulating security monitoring, detection, and response workflows. While the core infrastructure is in place, significant work remains to fully operationalize the environment.

The next steps include:
- Configuring and tuning the SIEM to improve correlation rules, dashboards, and alert accuracy.
- Refining Suricata and firewall rules to better detect and block malicious activity.
- Integrating additional threat intelligence feeds into TheHive and OpenCTI for enriched alert context.
- Simulating advanced attack scenarios to test detection and response capabilities in realistic conditions.
- Automating incident workflows using SOAR tools like Shuffle.

This lab is designed to evolve over time. As you continue refining configurations, expanding integrations, and testing new detection logic, it will more closely resemble a production-grade SOC environment.

Thank you for reading this documentation.
