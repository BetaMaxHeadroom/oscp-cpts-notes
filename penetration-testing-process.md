# Penetration Testing Process

`We should slowly continue to build our skills in all areas to become as well-rounded as possible while striving for expert-level knowledge in at least one discipline.`

we are exam ready if we can solve last module `AEN` blind.

### **Penetration Tester Path Syllabus**

## Introduction

1. Penetration Testing Process
2. Getting Started

### Reconnaissance, Enumeration & Attack Planning

1. Network Enumeration with Nmap
2. Foot printing
3. Information Gathering - Web Edition
4. Vulnerability Assessment
5. File Transfers
6. Shells & Payloads
7. Using the Metasploit Framework

### Exploitation & Lateral Movement

1. Password Attacks
2. Attacking Common Services
3. Pivoting, Tunneling, and Port Forwarding
4. Active Directory Enumeration & Attacks

### Web Exploitation

1. Using Web Proxies
2. Attacking Web Applications with Ffuf
3. Login Brute Forcing
4. SQL Injection Fundamentals
5. SQLMap Essentials
6. Cross-Site Scripting (XSS)
7. File Inclusion
8. File Upload Attacks
9. Command Injections
10. Web Attacks
11. Attacking Common Applications

### Post-Exploitation

1. Linux Privilege Escalation
2. Windows Privilege Escalation

### Reporting & Capstone

1. Documentation & Reporting
2. Attacking Enterprise Networks

### Academy Modules Layout

<figure><img src=".gitbook/assets/Untitled (1).png" alt=""><figcaption></figcaption></figure>

### Pre-Engagement

<figure><img src=".gitbook/assets/Untitled (2).png" alt=""><figcaption></figcaption></figure>

The pre-engagement stage is where the main commitments, tasks, scope, limitations, and related agreements are documented in writing. During this stage, contractual documents are drawn up, and essential information is exchanged that is relevant for penetration testers and the client, depending on the type of assessment.

#### \*\*1. Learning Process

2. Linux Fundamentals
3. Windows Fundamentals
4. Introduction to Networking
5. Introduction to Web Applications
6. Web Requests
7. JavaScript Deobfuscation
8. Introduction to Active Directory
9. Getting Started\*\*

## **Information Gathering**

<figure><img src=".gitbook/assets/Untitled (3).png" alt=""><figcaption></figcaption></figure>

![](https://prod-files-secure.s3.us-west-2.amazonaws.com/bed36b1f-6a89-4b97-8ce1-d98b6498d046/35a0d39f-eb4f-4d30-8e5f-872e016b8b14/Untitled.png)

#### \*\*10. Network Enumeration with Nmap

11. Footprinting
12. Information Gathering - Web Edition
13. OSINT: Corporate Recon\*\*

## **Vulnerability Assessment**

<figure><img src=".gitbook/assets/Untitled (4).png" alt=""><figcaption></figcaption></figure>

#### \*\*14. Vulnerability Assessment

15. File Transfers
16. Shells & Payloads
17. Using the Metasploit-Framework\*\*

## **Exploitation**

<figure><img src=".gitbook/assets/Untitled (6).png" alt=""><figcaption></figcaption></figure>

#### \*\*18. Password Attacks

19. Attacking Common Services
20. Pivoting, Tunneling & Port Forwarding
21. Active Directory Enumeration & Attacks\*\*

### **Web Exploitation**

2nd part of exploitation stage.

#### \*\*22. Using Web Proxies

23. Attacking Web Applications with Ffuf
24. Login Brute Forcing
25. SQL Injection Fundamentals
26. SQLMap Essentials
27. Cross-Site Scripting (XSS)
28. File Inclusion
29. Command Injections
30. Web Attacks
31. Attacking Common Applications\*\*

## **Post-Exploitation**

<figure><img src=".gitbook/assets/Untitled (7).png" alt=""><figcaption></figcaption></figure>

#### \*\*32. Linux Privilege Escalation

33. Windows Privilege Escalation\*\*

## **Lateral Movement**

<figure><img src=".gitbook/assets/Untitled (8).png" alt=""><figcaption></figcaption></figure>

## **Proof-of-Concept**

The `Proof-Of-Concept` (`POC`) is merely proof that a vulnerability found exists. As soon as the administrators receive our report, they will try to confirm the vulnerabilities found by reproducing them

| Path            | Description                                                                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Post-Engagement | At this point, we can only go to the post-engagement stage, where we optimize and improve the documentation and send it to the customer after an intensive review. |

#### **34. Introduction to Python 3**

## **Post-Engagement**

The `Post-Engagement` stage also includes cleaning up the systems we exploit so that none of these systems can be exploited using our tools.

#### \*\*35. Documentation & Reporting

36. Attacking Enterprise Networks\*\*

### Penetration Testing Overview

### **Testing Methods**

* External Penetration Test
  * External penetration testing consists of testing vulnerabilities to review the chances of being attacked by any remote attacker.
* Internal Penetration Test
  * when we perform testing from within the corporate network.

### **Types of Penetration Testing**

| Type           | Information Provided                                                                                                                                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Blackbox       | Minimal. Only the essential information, such as IP addresses and domains, is provided.                                                                                                                                                                             |
| Greybox        | Extended. In this case, we are provided with additional information, such as specific URLs, hostnames, subnets, and similar.                                                                                                                                        |
| Whitebox       | Maximum. Here everything is disclosed to us. This gives us an internal view of the entire structure, which allows us to prepare an attack using internal information. We may be given detailed configurations, admin credentials, web application source code, etc. |
| Red-Teaming    | May include physical testing and social engineering, among other things. Can be combined with any of the above types.                                                                                                                                               |
| Purple-Teaming | It can be combined with any of the above types. However, it focuses on working closely with the defenders.                                                                                                                                                          |

| Stage                       | Description                                                                                                                                                                                                                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1. Pre-Engagement           | The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions.                                                                                                                                         |
| 2. Information Gathering    | Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions.                                                                           |
| 3. Vulnerability Assessment | With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions.                                                                                                                                                  |
| 4. Exploitation             | Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities.                                                                                                                              |
| 5. Post-Exploitation        | Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations).                          |
| 6. Lateral Movement         | If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered.                                                                                                        |
| 7. Proof-of-Concept         | We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities.                                                                                                                           |
| 8. Post-Engagement          | Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings. |

## **Information Gathering**

* Open-Source Intelligence
* Infrastructure Enumeration
* Service Enumeration
* Host Enumeration

## Practicing Steps

* 2x Modules
* 3x Retired Machines
* 5x Active Machines
* 1x Pro Lab / Endgame

## Here is a good blueprint for tackling a module:

| Step | Task                                                  |
| ---- | ----------------------------------------------------- |
| 1.   | Read the module                                       |
| 2.   | Practice the exercises                                |
| 3.   | Complete the module                                   |
| 4.   | Start the module exercises from scratch               |
| 5.   | While solving the exercises again, take notes         |
| 6.   | Create technical documentation based on the notes     |
| 7.   | Create non-technical documentation based on the notes |

When we have completed (at least) two modules and are satisfied with our notes and documentation, we can select three different retired machines. These should also differ in difficulty, but we recommend choosing `two easy` and `one medium` machines.

The order in which we can proceed to practice with the retired machines looks something like this:

| Step | Task                                                                                                                                                                  |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.   | Get the user flag on your own                                                                                                                                         |
| 2.   | Get the root flag on your own                                                                                                                                         |
| 3.   | Write your technical documentation                                                                                                                                    |
| 4.   | Write your non-technical documentation                                                                                                                                |
| 5.   | Compare your notes with the official write-up (or a community write-up if you don't have a VIP subscription                                                           |
| 6.   | Create a list of information you have missed                                                                                                                          |
| 7.   | Watch [https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) walkthrough and compare it with your notes |
| 8.   | Expand your notes and documentation by adding the missed parts                                                                                                        |

Ideal practice steps for active machines would look like this:

| Step | Task                                                     |
| ---- | -------------------------------------------------------- |
| 1.   | Get the user and root flag                               |
| 2.   | Write your technical documentation                       |
| 3.   | Write your non-technical documentation                   |
| 4.   | Have it proofread by technical and non-technical persons |
