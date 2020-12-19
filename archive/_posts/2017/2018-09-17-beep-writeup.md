---
layout: post
title:	"Beep Writeup"
date:	2018-09-17 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - hackthebox
---
<head>
	<title> Beep Writeup | HackTheBox </title>
</head>

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/logo.png)

Note: This machine has multiple ways to root.

## i. Port Scan

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/ports.png)

## ii. Root #1

Port 10000 (Webmin) looked interesting to me.

Navigating in the browser:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/webmin.png)

Webmin uses the local accounts on the server to login. 

While enumerating Webmin, I noticed that requests are processed by CGI:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/cgi.png)

Could this potentially be vulnerale to Shellshock?

Attempting to use a payload which will print the user if successful:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/shellshock.png)

Looking at the page, it seems that nothing has changed:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/webmin2.png)

Let's try using a blind payload, which does not rely on the output. 

`An example of some blind commands: sleep, wget.`

I'm going to use wget, and setup a HTTP server using python and see if the request gets made. (Assuming wget is installed on the host)

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/wget.png)

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/request.png)

We see that the host is trying to download a file off our host, which means we have code execution!

Replacing the Shellshock payload with a `bash reverse shell one-liner`:

~~~
More reverse shell one-liners:
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/oneliner.png)

After sending the request, if we look at our listener:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/shell1.png)

We successfully got a reverse shell.

And it looks like we are already root:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/root1.png)

## iii. Root #2

Navigating to port 443 in the browser, we see a login for Elastix:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/elastix.png)

`Trying all the default passwords does not work`

Running a gobust on the host to see if we can find any interesting directories:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/gobuster.png)

After enumerating most of the directories, one stood out: `vtigercrm`:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/vtigercrm.png)

If we look at the footer, we see a version number:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/vtigerversion.png)

Searching for any exploits, one seems to match: 

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/searchsploit.png)

Looks like vTiger is vulnerable to Local File Inclusion, which means we can view files located on the host.

Viewing /etc/passwd, and getting a username: `fanis`

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/passwd.png)

Also in /etc/passwd, we see an entry for `asterisk`

Asterisk is an open source PBX software.

~~~
https://www.asterisk.org/
~~~

Asterisk has a configuration file located in `/etc/asterisk/manager.conf` which has configuration details such as passwords.

Using the LFI in VTiger to read the asterisk configuration:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/asterisk.png)

The highlighted string contains the username and password.

`admin:jEhdIekWmdjE`

These details can be used for this exploit: https://www.rapid7.com/db/modules/exploit/multi/http/vtiger_soap_upload

Also, while trying password reuse with different users, the asterisk password is the same as root's password:

![Screenshot]({{ site.baseurl }}/images/posts/2017/beep/root2.png)


## iv. Conclusion

I enjoyed this box a lot because there are multiple ways to gain access. I've included most of the ways, but there are a few left. 
This box is somewhat realistic aswell, because sysadmins can be lazy and reuse the same password multiple times.

Thanks for reading.


~~~
Sources / Links:
[0]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
[1]: https://www.asterisk.org/
~~~


