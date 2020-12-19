---
layout: post
title:	"Dummy Writeup | Wizard-Labs"
date:	2019-01-20 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - wizardlabs
---
<head>
	<title> Dummy Writeup | Wizard-Labs </title>
</head>
![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/logo.jpg)

## i. Port Scan

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/ports.png)

## ii. Enumeration

First, we can start off by listing the SMB shares to see if there is anything interesting:

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/smbshares.png)

Seems like guests are not allowed to view shares...


Moving onto the next port... 8000.

Nmap's service detection shows that the service is `Icecast streaming media server`.

To confirm that the service is indeed Icecast, we can visit port 8000 in the browser:

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/error.png)

If you google the error, you will see Icecast help forums pop up.

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/search.png)

With the information in mind, we can use searchsploit to see if there are any Icecast exploits.

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/searchsploit.png)

As we do not know the version number, we will have to guess. Though looking at the exploits, the only ones that look interesting are the remote code execution.

We can use `Metasploit` to gain command execution:

~~~
Module: https://www.rapid7.com/db/modules/exploit/windows/http/icecast_header
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/msf.png)

Checking to see which user Icecast was running under... it was Administrator.

![Screenshot]({{ site.baseurl }}/images/posts/2017/dummy/admin.png)

The attack on this box can have been prevented in two ways:

~~~
a. Make sure to routinely patch, and keep software updated
b. Do not run software under a high privileged account, make a separate service account if needed.
~~~

## iii. Conclusion

Dummy is a good beginner box. It shows the importance of fingerprinting software, and knowing which exploits to use.

If you would like to try Dummy & other OSCP-like boxes, try it on **Wizard-Labs**: http://labs.wizard-security.net/

Thank you for reading.

Sources/Links:
~~~
[0]: http://labs.wizard-security.net/
~~~


