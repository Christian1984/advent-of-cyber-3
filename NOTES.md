https://tryhackme.com/room/adventofcyber3

# Day 1 - Cookies

## Video Walkthrough

- https://www.youtube.com/watch?v=858rVeWB8Pw

## Learning Objectives

- What is an IDOR vulnerability?
- How do I find and exploit IDOR vulnerabilities?
- Challenge Walkthrough.

## Notes

- if user ids, product ids etc. are used as a query parameter, cookie parameter or form parameter/post value, try playing around with it and brute force for other values accepted by the server.

## Resources

- https://corneacristian.medium.com/top-25-idor-bug-bounty-reports-ba8cd59ad331

---

# Day 2 - Cookies

## Video Walkthrough

- https://www.youtube.com/watch?v=8XYtpv-3-No

## Learning Objectives

- Understanding the underlying technology of web servers and how the web communicates.
- Understand what cookies are and their purpose.
- Learn how to manipulate and manage cookies for malicious use.

## Notes

- use browser dev tools to check cookies
- use cyberchef and "Magic" operation to identify encoding (https://gchq.github.io/CyberChef/)
- change values and reencode
- update cookie with new encoded value
- refresh website

## Resources

- https://tryhackme.com/jr/authenticationbypass

---

# Day 3 - Content Discovery

## Video Walkthrough

- https://www.youtube.com/watch?v=8dUylKcDUvU

## Learning Objectives

- In today's task, we're going to be using our investigatory skills and techniques to discover un-listed content, and attempt some common authentication using the clues around us.

## Notes

- Connect to TryHackMe VPN with `openvpn openvpn.ovpn` to connect using the openVPN profile provided by TryHackMe
- Use `dirb http://{ip/url} /urs/share/wordlists/dirb/common.txt` for example to discover resources exposed by the server

## Resources

- https://tryhackme.com/jr/contentdiscovery

---

# Day 4 -  Authentication and Fuzzing

## Video Walkthrough

- https://www.youtube.com/watch?v=jT8-HE95G5Q

## Learning Objectives

- Understanding authentication and where it is used
- Understanding what fuzzing is
- Understanding what Burp Suite is and how we can use it for fuzzing a login form to gain access
- Apply this knowledge to retrieve Santa’s travel itinerary 

## Notes

### Terms and Tools

- AUTHENTICATION is the process of verifying a user's identity
- AUTHORISATION defines what an authenticated user can or cannot access
- FUZZING describes automated means of tempering with the element of a website until it exposes a vulnerability
- Burp Suite is a fuzzing tool set

### Configuration

- Install FoxyProxy Extension
- Configure Proxy with parameters from BurpSuite -> Proxy -> Options
- Navigate to 127.0.0.1:8080 (or whatever the burp suite configuration is) and install the root certificate like so: https://null-byte.wonderhowto.com/how-to/use-burp-foxyproxy-easily-switch-between-proxy-settings-0196630/

### The Attack

- Navigate to login form that should be attacked
- Set FoxyProxy to BurpSuite proxy
- Make sure that Proxy->Intercept Is On is checked
- Login with random credentials
- In BurpSuit, right click request, then "Send to Intruder"
- Go to intruder
- Select attack type "Sniper" if username is known, otherwise "Cluster Bomb"
- Setup payload positions
- Go to Payloads
- Load Wordlist(s)
- Start attack
- Responses for wrong passwords will usually have same length, those for correct passwords will result in a response of different length

## Resources

- https://tryhackme.com/room/principlesofsecurity

---

# Day 5 - XSS / Cross Site Scripting

## Video Walkthrough

- https://www.youtube.com/watch?v=uA1OHCgArzI

## Learning Objectives

- What is an XSS vulnerability?
- What Types of XSS vulnerabilities are there?
- Challenge Walkthrough.

## Resources

- https://tryhackme.com/room/xssgi
---

# Day 6 - Local File Intrusion Vulnerability (LFI)

## Video Walkthrough

- https://www.youtube.com/watch?v=pGPE5uCI5h8

## Learning Objectives

- Understanding the basics of a Local File Inclusion (LFI) vulnerability
- Learn how to identify and test for LFI
- Understanding the possible the impact of an LFI vulnerability by exploiting it

## Notes

- An LFI can occur when a developer includes local files based on user input and without properly validating and sanitizing it.
- In some cases an LFI could even be chained with a remote code execution attack (RCE) if content can be written to and/or injected into a file on the local file system.

- After inspecting the application it becomes obvious that with the entrypoint (or request param `?err=[filename]`) an LFI can be exploited. 
- Files on the local file could potentially with `?err=/etc/passwd` for example.
- Similarly, a php file could be read like this. But since it would be executed, a filter function must be used to encode it first, like so: `https://10-10-84-73.p.thmlabs.com/index.php?err=php://filter/convert.base64-encode/resource=index.php`
- The content can the be decoded via the command line like so: `echo "QW9DMyBpcyBmdW4hCg==" | base64 --decode AoC3 is fun!`

- Vice versa code can be injected by base64 encoding it (e.g. `echo "AoC3 is fun!" | base64 QW9DMyBpcyBmdW4hCg==`)
- ... and then append it to the url as `https://10-10-84-73.p.thmlabs.com/index.php?err=data://text/plain;base64,QW9DMyBpcyBmdW4hCg==`

## Resources

- https://tryhackme.com/module/how-the-web-works
- https://tryhackme.com/room/fileinc
- https://www.php.net/manual/en/wrappers.php.php

---

# Day 7 - NoSQL Injection

## Video Walkthrough

- https://www.youtube.com/watch?v=Fmw8ia0sMEc

## Learning Objectives

- What is NoSQL?
- Understanding NoSQL database
- Understand Why NoSQL happens
- Understand what NoSQL injection is
- Using NoSQL Injection to bypass a login form

## Notes

- Connect to a local mongo db instance via CL with `mongo`
- Use `show databases` to list all available DBs
- `use mydb` connects to the db `mydb`. If it does not exists yet, it will be created
- `db.getCollectionNames()` lists all collections in a given DB
- `db.createCollection("my_collection")` creates a new collection named `my_collection`
- `db.my_collection.insert({id: "1", name: "apple"})` inserts a new object into the collection
- `db.my_collection.find({id: "1"})` finds the entry with `id==1` in collection `my_collection`
- `db.my_collection.update({id: "1"}, {$set: {name: "banana"}})` updates the name property of the entry with `id==1` in collection `my_collection`
- `db.my_collection.delete({id: "1"})` deletes the entry with `id==1` from `my_collection`

- For an NoSQL-Injection exploit via JSON (e.g. through an API or such), an attack could look like replacing the password with a wrong guess and then negating it, e.g. `{$ne:"xyz"}`. If the server now runs a query like `db.users.findOne({user: "admin", password: {$ne:""xyz}})` it will return a result and if the server code is written with little security in mind, this could allow us to access the server.
- For an NoSQL-Injection exploit via a POST or GET request, it is usually necessarry to inject an array of the MongoDB operator, eg. `http://example.thm.labs/login?username=admin&password[$ne]=xyz`.
- For POST requests, use burp suite's repeater to modify the request parameters before forwarding it to the server.

## Resources

- https://bsonspec.org/
- https://docs.mongodb.com/manual/reference/operator/query/

---

# Day 8 - PowerShell Transcription Logs

## Video Walkthrough

- https://www.youtube.com/watch?v=oGX7vLtjbic

## Learning Objectives

- Familiarization with working through log files
- Searching for clues and following them to find the solution to a given problem

## Notes

- RDP into the target machine with `xfreerdp /u:Administrator /p:grinch123! /v:10.10.33.129`
- The copy and encryption logs are found in `PowerShell_transcript.LAPTOP.Zw6PA+c4.20211128153734` (third log-file in terms of timeline)
- The `UsrClass.dat` file can be decoded with either `base64 --decode` on linux or `certutil -decode [source] [target]` on windows, or with CyberChef. Finally, view it with `ShellbagsExlorer`
- The password was hidden in the repos commit messages. When viewed on github, make sure to click the `...` to fully expand the commit message (duh!)

## Resources

- https://tryhackme.com/module/windows-fundamentals
- https://lolbas-project.github.io/lolbas/Binaries/Certutil/
- https://www.sans.org/tools/shellbags-explorer/

---

# Day 9 - Analyzing Traffic with Wireshark

## Video Walkthrough

- https://www.youtube.com/watch?v=LnBT1qubCnc

## Learning Objectives

- Basic skills and knowledge to perform a basic packet analysis using Wireshark

## Notes

- Packets can be filtered by many different properties. Examples include protocols (`http`, `ftp`, `dns` etc.) and http methods (`http.request.method == GET`)
- Right clicking a packet and then clicking `follow TCP stream` (or `http stream`) can be used to follow the communication for that particular packet
- Individual Header Sections can be expanded by clicking the `>` next to it!

## Resources

- https://en.wikipedia.org/wiki/Berkeley_Packet_Filter

---

# Day 10 - 

## Video Walkthrough

- https://www.youtube.com/watch?v=yHjD_07r5xs

## Learning Objectives

- Familiarization with `nmap` and how to use it to scan for services and open ports on a target machine
- Using this information to further research vulnurabilities on the target machine

## Notes

- Run `nmap -sC {ip}` to scan the target host for open ports and associated services. `-sC` tries to completely connect by running the full 3-way-handshake, `-sS` does not connect, `-sV` scans for the version running
- Knowing the version number of a given service, e.g. the webserver running on a system, one can check publicly available resources for known vulnerabilities, e.g. https://httpd.apache.org/security/vulnerabilities_24.html
- Adding the option `-p1-65535` or `-p-` scans for all ports rather than just the most standard 1000 ports

## Resources

- https://tryhackme.com/jr/protocolsandservers
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://tryhackme.com/module/network-security

---

# Day 11 - Probe Database Server

## Video Walkthrough

- https://www.youtube.com/watch?v=VJ2YFzTMqNY

## Learning Objectives

- learn how to use `sqsh` to interact with a MS SQL Server
- learn that if xp_cmdshell is enabled, you can execute system commands and read the output using sqsh

## Notes

- If a server appears to be down to nmap, use flag `-Pn` to skip pinging the machine first. nmap now assumes that the machine is online...
- Use `sqsh -S [ip] -U [username] - P [passwd]` to access a MS SQL server through the CL.
- Use `EXEC sp_databases;` to discover databases on the server. Execute with `go`!
- Use `use db` to access database `db`
- Use `SELECT * FROM db.INFORMATION_SCHEMA.TABLES;` to discover tables in a `db`.
- Use `xp_cmdshell "command";` to run shell commands through sqsh, e.g. `xp_cmdshell "whoami"; go` will return the current user.

## Resources

- 

---

# Day 12 - Discovering and Mounting Shares

## Video Walkthrough

- https://www.youtube.com/watch?v=BQqjJwFLLII

## Learning Objectives

- Learn how to use nmap to discover fileservers
- learn how to discover and mount shares
- learn how to calculate a fingerprint of a file

## Notes

- discover ports and associated services with `nmap`, use `-Pn` where appropriate
- if `nfs` or `mountd` was discovered, discover shares with `showmount -e <ip>`
- mount shares with `sudo mount <ip>:/<sharename> <mountdir>`
- calculate the MD5 hash of a file with `md5sum <filename>`

## Resources

- N/A

---
---
---

# Day X - 

## Video Walkthrough

- 

## Learning Objectives

- 

## Notes

- 

## Resources

- 

