# roger-skyline-1
VM Part:

-> Virtual Machine Installation
: Instal Virtual Box VM 
: Create a new Debian Virtual Machine 
: Choose a hostname 
: Setup the root password
: Create a non root user and a password
: Create a primary partition mounted on / with 4.2 GB of space and a other one as 
  logical mounted on /home 
: You can install the desktop environment or not
: Install GRUB on the master boot record

-> Keeping the VM up to date
: <<< sudo apt-get update -y && apt-get upgrade -y >>> 
  <<< sudo apt-get install portsentry fail2ban apache2 mailutils git -y >>>


NETWORK AND SECURITY PART:

Step 1: (Setting up Sudo rights for user)

        Firt we need to install the sudo package as root: apt-get install sudo
        Edit this file: cat /etc/sudoers : with the : visudo : command
        Output: 
        # This file MUST be edited with the 'visudo' command as root.
        #
        # Please consider adding local content in /etc/sudoers.d/ instead of
        # directly modifying this file.
        #
        # See the man page for details on how to write a sudoers file.
        #
        Defaults        env_reset
        Defaults        mail_badpass
        Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbi$

        # Host alias specification

        # User alias specification

        # Cmnd alias specification

        # User privilege specification
        root         ALL=(ALL:ALL) ALL
        ismelich     ALL=(ALL:ALL) NOPASSWD:ALL  <--------------- ADD THE USER HERE

        # Members of the admin group may gain root privileges

        # Allow members of group sudo to execute any command
        %sudo   ALL=(ALL:ALL) ALL

        # See sudoers(5) for more information on "#include" directives:

        #includedir /etc/sudoers.d

Step 2: (Setup a static IP)

        First we need to change the network settings of our Virtual Box Machine
        The default Network Adapter is 'NAT', we need to change it to 'Bridge Adapter'
        -----------------------------------------------------------------------------
        Now we need to edit the file /etc/network/interfaces
        The Output should look like this:
        source /etc/network/interfaces.d/*

        #The loopback Network interface
        auto lo
        iface lo inet loopback

        #The primary network interface
        auto enp0s3
        -----------------------------------------------------------------------------
        Now we need to configure this network with a static ip, we need to create a
        file name 'enp0s3' int the following directory 'etc/network/interfaces.d/'
        The Output should look like this:
        iface enp0s3 inet static
              address 10.12.181.**
              netmask 255.255.255.252
              gateway 10.12.254.254
        
        Subnet Mask: http://www.sput.nl/internet/netmask-table.html
        We can get the gateway IP with this command <<<ip r | grep default>>>
        -----------------------------------------------------------------------------
        In order to test if our change was successful, we need to restart the network
        sudo service networking restart
        And run this command to see if the changes applied
        <<<ip a>>> 
        -----------------------------------------------------------------------------

Step 3: (Changing the default Port of the SSH service)

        First we need to edit the sshd configuration file:
        <<<sudo vim /etc/ssh/sshd_config>>>
        We need to change the port which is in default commented out at the line 13
        Port 63636
        IMPORTANT NOTE:
        Port numbers are assigned in various ways, based on three ranges: System
        Ports (0-1023), User Ports (1024-49151), and the Dynamic and/or Private
        Ports (49152-65535); the difference uses of these ranges is described in
        [RFC6335]. According to Section 8.1.2 of [RFC6335], System Ports are 
        assigned by the "IETF Review" or "IESG Approval" procedures described in 
        [RFC8126]. User Ports are assigned by IANA using the "IETF Review" process, 
        the "IESG Approval" process, or the "Expert Review" process, as per 
        [RFC6335]. Dynamic Ports are not assigned.
        Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
        -----------------------------------------------------------------------------
        Now it is possible to login wiht ssh wiht our new assigned port:
        <<<ssh ismelich@10.12.181.** -p 50683>>>
        -----------------------------------------------------------------------------

Step 4: (SSH access with publickeys)

        First, we need to generate a public + private rsa key pair on our host Machine
        It must be generated in our ~/.ssh folder.
        ssh-keygen -t rsa
        This command will generate 2 files you can call them id_rsa, it will generate
        id_rsa: our private key. the private key is stored on your local computer and
                should be kept secure, wiht permissions set so that no other users can
                read the file.
        id_rsa.pub: a public key, the public key is placed on the server you intend to
                    log in to. You can freely share your public key with others. if
                    someone else adds your public key to their server, you will be
                    able to log in to that server.
        Source: https://www.linode.com/docs/security/authentication/use-public-key-authentication-with-ssh/#connect-to-the-remote-server
        ------------------------------------------------------------------------------
        In order to transfer our public key to our server we to run this command
        <<<ssh-copy-id -i id_rsa.pub ismelich@10.12.181.** -p 63636>>>
        The public key will be added automatically in: ~/.ssh/authorized_keys 
        on the server.
        ------------------------------------------------------------------------------
        Now we need to remove the root login permit and the password authentification
        We need to edit our sshd_confg file in /etc/ssh/sshd.config
        Edit line 32: PermitRootLogin no
        Edit line 37: PubkeyAuthentication yes
        Edit line 56: PasswordAuthentication no
        *DONT FORGET TO REMOVE THE COMMENT SIGNS BEFORE THE COMMANDS '#'*
        ------------------------------------------------------------------------------
        Restart the SSHD daemon service 
        <<< sudo service sshd restart >>>
        No we are abble to connect to the server via ssh wiht the public key wihtout
        typing in the password and login into the root will not be possible.
        ------------------------------------------------------------------------------

Step 5: (Setting up the Firewall with UFW)

        First we check if ufw is enabled with the command:
        <<< sudo ufw status >>>
        If it is not enabled, stat the servie with this command:
        sudo ufw enable 
        ------------------------------------------------------------------------------
        Now we need to setuo firewall rules with this commands:
        <<< sudo ufw allow 63636/tcp >>> Allowing incoming SSH connections
        <<< sudo ufw allow 80/tcp >>> Allowing incoming HTTP(port 80) connections 
        <<< sudo ufw allow 443 >>> Allowing incoming HTTPS (port 443) connections 
        More info: https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands
        ------------------------------------------------------------------------------
        Now we need to set up the Denial Of Service Attack with fail2ban
        <<< sudo-apt get install fail2ban >>>
        We need to edit the jail.conf in the fail2ban folder, but we need to make adding
        copy of the fail, otherwise the conf file will reset itself to default.
        <<< sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local >>>
        ------------------------------------------------------------------------------
        Now we can edit the jail.local file, the Jail part inside the file should 
        look like this:
        [sshd]
        enabled = true
        port    = ssh 
        logpath = %(sshd_log)s
        backend = %(sshd_backend)s
        maxretry = 3
        bantime = 600

        #Add after HTTP servers:
        [http-get-dos]
        enabled = true
        port = http,https
        filter = http-get-dos
        logpath = /var/log/apache2/access.log
        maxretry = 300
        findtime = 300
        bantime = 600
        action = iptables[name=HTTP, port=http, protocol=tcp]
        ------------------------------------------------------------------------------
        Now we need to create a http-get-dos.conf inside this folder 
        /etc/fail2ban/filter.d 
        The output should look like this: 
        [Definition]
        failregex = ^<HOST> -.*"(GET|POST).*
        ignoreregex =
        ------------------------------------------------------------------------------
        Last but not least we need to reload our firewall and fail2ban:
        <<< sudo ufw reload >>>
        <<< sudo service fail2ban restart >>>
        ------------------------------------------------------------------------------
        We can test if the new conf works with SlowLoris (an HTTP DDOS attack script)
        install git: <<< sudo apt-get install git >>>
        install SlowLoris: <<< git clone https://github.com/gkbrk/slowloris.git >>>
        Run the program: perl slowloris.py 10.13.200.**
        -----------------------------------------------------------------------------
        To see if our new fail2ban conf actually works we need to check the following
        file: ~/var/log/fail2ban.log 

Step 6: (Setting up protection agains port scans)

        First we need to install the nmap tool with <<< sudo apt-get install nmap >>>
        Nmap is a free and open source netwokr discovery and security utility. It works
        by ssending data packets on a specific target and by interpreting the incoming
        packets to determine what ports are open or closed.
        We get the following output if we run nmap:
        ismelich@ilja:~$ sudo nmap 10.12.181.98
        Starting Nmap 7.70 ( https://nmap.org ) at 2019-12-16 12:09 EET
        Nmap scan report for 10.12.181.98
        Host is up (0.0000060s latency).
        Not shown: 984 closed ports
        PORT      STATE SERVICE
        1/tcp     open  tcpmux
        79/tcp    open  finger
        80/tcp    open  http
        111/tcp   open  rpcbind
        119/tcp   open  nntp
        143/tcp   open  imap
        1080/tcp  open  socks
        1524/tcp  open  ingreslock
        2000/tcp  open  cisco-sccp
        6667/tcp  open  irc
        12345/tcp open  netbus
        31337/tcp open  Elite
        32771/tcp open  sometimes-rpc5
        32772/tcp open  sometimes-rpc7
        32773/tcp open  sometimes-rpc9
        32774/tcp open  sometimes-rpc11
        ------------------------------------------------------------------------------
        Now we need to edit the /etc/default/portsentry file. Output:
        TCP_MODE="atcp" portscan detection advanced mode 
        UDP_MODE="audp" advanced portscan detection on specified ports 
        ------------------------------------------------------------------------------
        Now we need to edit the portsentry.conf file inside /etc/portsentry 
        Change the following entires:
        BLOCK_UDP="1"   
        BLOCK_TCP="1"   Block UDP/TCP scans with 1.
        ------------------------------------------------------------------------------
        Comment the current KILL_ROUTE command and uncomment the following one:
        KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
        This will drop all packets originating from an attacker’s IP address and 
        log future connection attempts.
        ------------------------------------------------------------------------------
        Comment the this command out:
        KILL_HOSTS_DENY="ALL: $TARGET$ : DENY
        So the SSH access is not denied.
        ------------------------------------------------------------------------------
        Now restart the portsentry service:
        <<< sudo service portsentry restart >>>
        ------------------------------------------------------------------------------
Step 7 (Stop services you don't need for this project)

        First we need to check which services are running wiht this command:
        <<<sudo service --status-all>>> or 
        <<< sudo systemctl list-unit-files --type=service | grep enabled >>>
        Services we don't need:
        sudo systemctl disable console-setup.service
        sudo systemctl disable keyboard-setup.service
        sudo systemctl disable apt-daily.timer
        sudo systemctl disable apt-daily-upgrade.timer
        sudo systemctl disable syslog.service
        ------------------------------------------------------------------------------

Step 8 (Scheduled updating of packages and monitoring changes)

        First we need to create a shell script file for the daily updates inside
        ~, it needs to be executable:
        echo "sudo apt-get update -y >> /var/log/update_script.log" >> ~/update.sh
        echo "sudo apt-get upgrade -y >> /var/log/update_script.log" >> ~/update.sh
        ------------------------------------------------------------------------------
        Now we need to create the notification scrips the informs the root about 
        the update via email, we create the file inside ~, it needs to be executeble:
        #!/bin/bash

        FILE="/var/tmp/checksum"
        FILE_TO_WATCH="/etc/crontab"
        MD5VALUE=$(sudo md5sum $FILE_TO_WATCH)

        if [ ! -f $FILE ]
        then
	 echo "$MD5VALUE" > $FILE
	 exit 0;
        fi;

        if [ "$MD5VALUE" != "$(cat $FILE)" ];
	then
	echo "$MD5VALUE" > $FILE
	echo "$FILE_TO_WATCH has been modified ! '*_*" | mail -s "$FILE_TO_WATCH modified! " root
        fi;
        ------------------------------------------------------------------------------
        In order to recieve the mail we need to install mailunits:
        <<< sudo apt install mailutils >>>
        <<< mailx >>> to see mails 
        We can check the recieved mail in /var/mail/
        ------------------------------------------------------------------------------
        Now we need to edit the crontab with the following command:
        <<< sudo crontab -e >>>
        @reboot sudo ~/update.sh 
        0 4 * * 7 sudo ~/update.sh 
        0 0 * * * sudo ~/monitor.sh 
        ------------------------------------------------------------------------------

Step 9 (Deployment of a web application with our vm IP)

        Copy or create a inde.html file into your /var/www/html folder which was 
        created with the installation of apache2
        -----------------------------------------------------------------------------

Step 10 (Self-signed SSl)

        A awesome tutorial which i followed step by step.
        https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-16-04
