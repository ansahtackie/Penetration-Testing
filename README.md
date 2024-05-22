# Penetration Testing

## Objective

The objective of this project was to perform penetration testing to assess the security posture of a network consisting of two Linux and two Windows machines. This involved compromising one Linux machine and leveraging it to pivot onto the remaining three machines, ultimately retrieving sensitive data. The findings and methodologies were documented in a comprehensive report.

## Skills Learned

#### Penetration Testing
- Expertise in identifying and exploiting vulnerabilities in Linux and Windows systems.
- Experience in conducting comprehensive security assessments.

#### Tools Proficiency
- Experience with penetration testing tools such as Metasploit, Nmap, and John the Ripper.
- Proficiency in scripting languages like Python for custom exploit development.


#### Problem Solving
- Analytical skills to troubleshoot and solve complex security issues.
- Creative thinking to find innovative solutions to bypass security measures.

#### Network Security
- Understanding of network architectures and common security protocols.
- Ability to analyze and secure network configurations.

#### Pivoting Techniques
- Proficiency in using compromised systems to access other machines within a network.
- Knowledge of lateral movement strategies and tools.

#### Linux and Windows Security
- In-depth knowledge of security practices and vulnerabilities specific to Linux and Windows operating systems.
- Experience in securing and hardening both types of systems.

#### Vulnerability Assessment
- Skill in identifying, assessing, and prioritizing vulnerabilities.
- Familiarity with tools and methodologies for vulnerability scanning.

#### Exploitation
- Ability to develop and execute exploits to gain unauthorized access to systems.
- Knowledge of post-exploitation techniques.

#### Data Retrieval
- Expertise in locating and extracting sensitive data from compromised systems.
- Understanding of data protection and encryption methods.

#### Report Writing
- Strong technical writing skills to document findings, methodologies, and remediation strategies.
- Ability to create comprehensive and clear reports for various stakeholders.


#### Communication 
- Ability to convey technical information clearly and effectively.
- Experience in presenting findings and recommendations to technical and non-technical audiences.




## Tools Used

- Kali Linux Machine used as the attacking machine.
- Nmap for running basic scans on a subnet.
- Two Ubuntu Machines used as target hosts.
- John The Ripper for cracking password from a password hash.
- Metasploit was used to develop and run exploit code on two Windows machines.


## Steps Used

####  Network Scanning
- Find the IP address of the attacking machine (Kali Linux Machine) using the ip a command.
  
   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/a247f27b-dfb8-4cfd-9f1c-4b3fe5d0aef8)

- Use Nmap to scan the subnet to identify target machines on the same subnet. There were four target machines; two Ubuntu and two Windows machines.
  
   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/b61de9db-d340-4a0f-8e88-398b4fa52603)

- Perform port scan for all the target machines.
  
  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/ab9eec60-9b38-4571-899e-d1d65e919953)
  
  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/797e48c8-d20d-4f85-9161-11bf7f6e8b46)

Perform service and version scans for the four target machiinces to find out the services being run on each machine. These scans were restricted to ports 1-5000 because of the scope of engagement.

![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/748f9389-b189-43f3-9f25-045ef3a94ac8)

*Table of IP Addresses of target machines, port numbers, and services*

The following screenshots show the scan for each of the four target machines

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/938bbbd0-3db3-4358-93a5-900e5d4ab85d)

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/10482c9e-6a2d-45b3-ba60-2a4df28fc630)

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/c2379dc9-1eaf-49e1-bb34-6730563e4396)

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/b18b2f5a-6262-4f20-917a-b71053a4c9c2)
  

##### Interpreting Scan Results

The service and version detection scans showed that there were two Ubuntu machines and two Windows-based machines. The following are the specific questions and answers based on the scope of engagement.


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/e416f1e3-3cc2-4b12-9bdc-1ac53940d90f)




####  Initial Compromise

- After running all the basic and service scans to identify all the host targets on the network, the next goal was to find our initial compromise vector. Servers hosting openly accessible services, like websites and unsecured databases, are a great place to begin. We realized that Ubuntu 22-1 was running HTTP service (Apache httpd 2.4.52) on a nonstandard port, port 1013, instead of running it on a default port, port 80. According to the Common Vulnerabilities and Exposure (CVE), the Apache httpd 2.4.52 has a vulnerability that allows an attacker to overwrite heap memory with possibly attacker-provided data. Based on these findings, we decided to exploit the Ubuntu 22-1 with IP address 172.31.33.97 first. We established a connection to this host using the unsecured opened port (1013).

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/2ae0a5c3-e7ae-46b4-94f1-0a266d177a76)


We established a successful connection to the website using the IP address and port number 1013.


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/b88513dd-15f6-406c-b619-953b20c6d8a9)


With an established link to the website, we exploited the site for important information that was used to gain access to the other hosts. Clicking on the “Network Utility Development Sites” gave us access to the Fullstack Academy.


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/b72ea3af-622d-4c32-a054-1d91f946e8bd)


This site had a part that accepted user input. We started exploiting this site using Command Injection.


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/02c1eea5-392a-4c54-a609-74de328af291)
     
 
  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/00088773-615b-4e61-a507-7ba6fbc26545)


Using the 172.31.33.97 ; cat /etc/passswd command, we were able to access the password of all the users on the Ubuntu-21 host.


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/1314b7aa-958a-4276-a54e-14b951a0c9bb)
     

*Note: This is not the full screen of all the users on the Ubuntu 22-1 host.*


We analyzed the etc/passwd output for possible passwords or other useful information that could help us compromise the other machines on the network. From our analyses, we found that there were some users who established login on the Ubuntu-22-1 host. These users were:
- root:x:0:0:root:/root:/bin/bash
- labsuser:x:1001:1001:,,,:/home/labsuser:/bin/bash
- alice-devops:x:1002:1002:,,,:/home/alice-devops:/bin/bash

Knowing that there were some users on the Ubuntu 22-1 hosts, we then decided to exploit further to get more information about these users. We run the 172.31.33.97 ; ls home command to see the content of the home directory. From this command, we found four users: 
- alice-devops
- labsuser
- ubuntu
- www-data
  
  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/6c4afe29-56f8-4364-822a-c0677a740dae)


####  Pivoting from Ubuntu 22-1 to Ubuntu 22-2

To pivot from Ubuntu 22-1 to Ubuntu 22-2, we wanted to establish ssh connection. To do this, we had to get ssh key. To obtain SSH from the web server, we decided to access the .ssh directory for all the users and read the content for SSH keys because we knew that SSH keys are typically saved in the users’ home directory in the .ssh directory. We also knew that SSH keys files are of the form “.pem”. With this information, we run commands to search for the SSH file. We started with the user alice-devops. With the localhost && ls /home/alice-devops/.ssh

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/e29ec0a9-c698-493d-9e2a-3f551585207a)


After accessing the id_rsa.pem file, we cat its content to access the required SSH key.


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/9277da55-b37f-4671-87c9-43cc6d9ca141)


The output of the command is shown below. The SSH key is the portion highlighted yellow.

- Server:		127.0.0.53
- Address:	127.0.0.53#53

- Name:	localhost
- Address: 127.0.0.1
- Name:	localhost
- Address: ::1


 ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/e03e040b-7583-4830-ab61-cea3d769397f)


##### Copying the SSH key on the Kali machine

The SSH key obtained from the compromised Linux machine (Ubuntu 22-1) was copied and saved as a id_rsa.pem file on the Kali host. We did this to be able to use the SSH key from the Kali machine to pivot into the second Linux machine.

 ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/366b371c-f02c-4fa9-8219-be7da8cd98dc)


##### Connecting from Kali machine to Ubuntu 22-2 machine

We used alice’s SSH key to connect from the Kali machine to the Ubuntu 22-2 machine. Ubuntu 22-2 machine was the second Linux server which was using nonstandard port (port 2222) to run ssh service. To establish the connection from the target machine (Kali machine) to the Ubuntu 22-2 machine, we had to set the permission of the id_rsa.pem file to give read, write, and execute permissions to only the user. The screenshot below shows the command and the output.

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/2761aa46-6be5-43ef-a385-3edd3f90b107)


  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/8a5b488d-92bd-4695-92a2-c96f7c080ff6)


With the new permissions on the SSH key file, we were able to establish a connection from the Kali machine into the Ubuntu 22-2 machine using the following command: Command: 
### sudo ssh -p 2222 -iid_rsa.pem alice-devops@172.31.36.185

The screenshot is shown below:

 ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/b4d5b164-1eed-441c-aacf-c683b5da4bc7)


####  System Reconnaissance

With the SSH access to the second Linux machine, our new goal was to move lateraly into the two Windows hosts. To do this, we wanted to search through the Linux machines for sensitive data, including passwords, keys, or hashes, that could be used to gain access to the Windows machines. 

##### Searching for files with sensitive information

With access to  Alice’s account on the Ubuntu 22-2, we decided to begin our exploit from there. We first used the ls -la command to list all the content on her home directory. Through the listing of all the content on the home directory, we found a directory labeled “scripts.” 

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/f79cbf51-a1b1-42a4-90a1-d55b3d2a1ae0)


This directory caught our attention, so we decided to look into the content of the “scripts” directory. We used the change directory (cd) command to get into to “script” directory. Inside the “script” directory we used the ls command to list the content of the directory. The content of this directory was a “.sh” file named “windows-maintenace.sh” 

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/292dac4e-0bb3-4a60-8ea6-0847ea950e08)


The “cat” command was then used to read the content of the windows-maintenance. sh file. The content of this file provided valuable information, including the username and password hash of the administrator.  

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/d94c893d-199b-4a0a-8798-774b20d7eccb)

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/90b859f4-f777-4faf-a4a1-7c3d27f2070e)

- Username = “Administrator
- Password_hash = "00bfc8c729f5d4d529a412b12c58ddd2"
- password= "00bfc8c729f5d4d529a412b12c58ddd2"
 

####  Password Cracking

With the username and password hash for the administrator, we cracked the password hash and used the username and password to laterally move from the Linux machine to the first Windows machine. 


##### Cracking Administrator Password

With the administrator password hash and knowing that the hash was a MD5 hash, we used John the Ripper to crack it for the actual password. John the Ripper is an open-source password security auditing and password recovery tool. It can crack passwords that have been hashed by several different hashing algorithms, including the ones used by the /etc/shadow file. John the Ripper supplies it with a file containing password hashes and tells it the kind of password hashes in the file, which is performed using the --format flag. Once provided, John will attempt to crack the passwords by generating different hashes to see if they match the ones provided in the password hash file. To use this tool from our Kali machine, we saved the password hash on our machine as file1.txt to create a file path for the password hash.

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/645971b3-a311-4a9c-a9a0-df1fe404ef18)


Using the options –wordlist, John the Ripper can accept a wordlist against the supplied password hash file. Because our Kali machine had the /usr/share/wordlists directory we were able to use the command john –wordlist=/usr/share/wordlists/john.lst file.txt –format=raw-md5 with sudo privilege to crack the password for the Administrator as “pokemon”

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/d6f60578-c7b0-4134-853b-d5f402ab3084)

So, we had the following information:

##### username: Administrator
##### password: pokemon



####  Metasploit

To establish a connection from our Kali machine to the first Windows machine, we used a Meterpreter shell. A Meterpreter shell provides shell access to a compromised system and the post modules that Metasploit provides. 

##### Starting the Metasploit Framework on Kali

To set up a Meterpreter session, we started the Metasploit framework on our Kali machine and loaded the windows/smb/psexec exploit module. This module is a common exploit for gaining access to Windows machines with stolen credentials. 

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/6e779694-65f3-4666-b931-dcf5c7945743)


   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/e4bca570-bb1c-420a-9bc9-f87861b0d00e)


##### Configuring the Module’s Options

After loading the exploit module, we configured the module's options to set the username and password we found previously (username: Administrator; password: pokemon). The RHOSTS was set to one of the Windows IP addresses (172.31.36.175). Finally, we set the payload to windows/x64/meterpreter/reverse_tcp. After setting all the information, we used the “check options” command to confirm all the settings.

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/0d6de684-e943-4cea-837c-b15e4d05907a)


Next, we ran the exploit to see if we could establish the Meterpreter session with the Windows machine with IP address 172.31.36.175. 

![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/9e9df7fd-fafb-4fb4-b09c-2fd739447644)

The first Windows machine could not establish a Meterpreter session with our Kali machine. Because we knew that the stolen credentials were going to work on one of the Windows targets, we tried the credentials on the second target machine with IP address 172.31.40.54

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/81bc1942-b9fc-43a2-92b5-dcd6421c0d3e)

As shown in the screenshot above, we established a connection on the second Windows target. So, this indicated that we laterally pivoted from the first Linux machine (Ubuntu 22-1) into the second Linux machine (Ubuntu 22-2) and then to one of the Windows machines.


####  Passing The Hash

With one Windows machine in our control, we used *Pass The Hash* attack to gain access to the second Windows machine. Pass The Hash attack is instrumental in lateral movement. Passing the hash takes advantage of the flaw in NTLM authentication, allowing you to utilize a user’s password hash without ever knowing the actual password. 

##### Performing Hash Dump

To continue from the initial Meterpreter session, we performed a hash dump and saved the result.

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/64253bc0-b3bf-4a93-be26-2e86bce2a94d)

The hash dump revealed the password hashes for all the users on the Windows machine. Included in the password hashes was the hash for Administrator2, shown below. 

##### aad3b435b51404eeaad3b435b51404ee:e1342bfae5fb061c12a02caf21d3b5ab

##### Establishing A Second Meterpreter Session

With the password hash for Admininstrator2, we wanted to use the Pass The Hash attack to establish a connection with the second Windows machine. To do this, we used the “background” command to exit the Meterpreter session to get back into the main Metasploit console. 

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/8c386ecb-add5-4f2e-bd7d-7ea11d500916)

Using the same exploit and payload modules, we set the RHOSTS target to the second Windows server IP address (172.31.36.175)


   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/cc3bbd2e-26d2-4c9b-b492-c292509e29e9)


We checked the options to confirm the configurations.

  ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/9f10d74d-e74e-4eb7-afd2-5fbec82a11ed)


After confirming the configurations, we ran the exploit. The exploit to the second Windows machine was successful.

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/2a5299e1-74da-49fd-8d7a-39bad06cca45)


With this connection, we were able to gain access to all four target machines. 



####  Finding Sensitive Files

With access to the final server, we wanted to search for a file and get its contents for our report.

##### Grabbing The Flag

From the Meterpreter session, we searched for the secrets.txt file using the command: 
search -f secrets.txt

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/f682812a-3d42-464f-b8f6-057f6b376f5f)


This search result provided a path for the secrets.txt file (c:\Windows\debug\secrets.txt). We then used the “cat” command to read the content of the file.

   ![image](https://github.com/ansahtackie/Penetration-Testing/assets/148600552/d35d89bf-36b4-4e56-973a-963a17f6b7b2)

The content of the secrets.txt file read, 
##### “Congratulations! You have finished the red team course!"


The final message in the secrets.txt file indicated that we have successfully completed all the challenges we set out to complete. 



