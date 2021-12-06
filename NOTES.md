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

