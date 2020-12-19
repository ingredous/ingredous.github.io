---
layout: post
title:	"Toppo Writeup"
date:	2018-07-14 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - vulnhub
---
<head>
	<title> Toppo Writeup | Vulnhub </title>
</head>
<title> Toppo Writeup </title>
![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/logo.png)

## i. Port Scan

Due to the machine displaying it's IP Address, I'm going to skip using netdiscover.

Running a port scan using unicornscan:

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/scan.png)

~~~
$ unicornscan -i eth0 Ir 160 10.0.2.9

-i = interface name
-I = immediately display results as they are found
-r = rate of packets to send per second

Source: https://tools.kali.org/information-gathering/unicornscan
~~~

## ii. Enumeration

Starting with port 80, we will use a web browser to browse to the host.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/web.png)

We are presented with a web page showing what looks like a blog. Checking the pages, we can see that each ends in .html, which makes this a static blog and makes it seem that PHP is not running on this webserver.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/menu.png)

Now to search for any hidden directories/pages and any files that end with .html & .txt.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/gobuster.png)

~~~
$ gobuster -u http://10.0.2.9 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 25 -x txt,html

-u = url
-w = wordlist to use
-t = threads
-x = file extensions

Source: https://tools.kali.org/information-gathering/unicornscan
~~~

Gobuster has found an /admin directory. Navigating to /admin, we see notes.txt:

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/notes.png)

notes.txt:
~~~
Note to myself : 

I need to change my password :/ 12345ted123 is too outdated but the technology isn't my thing i prefer go fishing or watching soccer .
~~~

Putting two-and-two together, a possible username for the password is `ted` (as ted is in the password string)

As we saw earlier, SSH is open. So we can try using `ted:12345ted123` with SSH.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/ssh.png)

Great, we got a user.

## iiia. Privilege Escalation Method #1

First thing I like to do when obtaining low privilege access is enumerate some information about the user.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/userenum.png)

~~~
$ id; sudo -l

id - displays information about our user, such as what groups they are in.
sudo -l  - displays if we can run any commands as sudo
~~~

So it seems like sudo is missing. To confirm it's not a PATH issue, I'll check if our $PATH is correct, and if sudo is installed.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/sudo.png)

~~~
$ echo $PATH
- Displays the PATH environment variable which stores directories in which executable files live.

$ dpkg -l | grep sudo
- Lists installed packages on the system, while piping the output to grep to search for sudo.
~~~

Seems like sudo is missing from the system. Interestingly enough, `/etc/sudoers` file exists.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/sudoers.png)

This could either be a hint, or a rabbithole. Start off by looking at the permissions that /usr/bin/awk has.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/awk.png)

It is being symlinked to `/etc/alternatives/awk`. We can use the `-L` switch to force `ls` to follow symlinks which will show the permissions of the file that `/usr/bin/awk` is linked to.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/mawk.png)

Looking at the permissions, we see the `s`.

Essentially the `s` means that this executable has a SUID bit. Which means that whenever this executable is run, it is temporary runs as the permissions of the file owner, in this case - root.

We are able to execute commands in awk, so running the file with `whomami` to see under which account the file is run:

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/whoami.png)

~~~
Awk is a utilty that can be used to manipulate and process text files. We are able to use system in awk to execute commands. In the above picture, we were able to execute whoami.
~~~

We are now executing commands as root. Let's spawn a shell.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/shell.png)

We now have root shell, box is pwned.

## iiib. Privilege Escalation Method #2

While initially enumerating this box, I was using a python to script to speed up the process. While looking at the output, I saw that it displayed my current logged in user as root EUID as 0.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/linuxprivchecker.png)

At first, I thought it was a glitch. Though, further investigating I realized that whenever we run python it is being run under root permissions. The biggest tip towards that was the EUID being 0.

The EUID is the Effective User ID. It changes for processes that the user executes that have the setuid bit set. 
```
Source: https://unix.stackexchange.com/questions/191940/difference-between-owner-root-and-ruid-euid
```

To confirm my findings, I searched for any files with SUID bits.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/sticky.png)

And.. python2.7 is on there. So whenever we run a script using python, it executes it under root privileges.

Essentially the same type of privilege escalation as awk above.

![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/pyroot.png)

## iv. Conclusion
![Screenshot]({{ site.baseurl }}/images/posts/2017/toppo/flag.png)

Nice box to practice some fundamentals. Thank you for reading. 

Box Link: https://www.vulnhub.com/entry/toppo-1,245/

Concepts in this box:
~~~
- Misconfigured SUID Bit Permissions
	- UID vs EUID
~~~ 

Sources/Links:
~~~
[0]: https://tools.kali.org/information-gathering/unicornscan
[1]: https://www.thegeekdiary.com/what-is-suid-sgid-and-sticky-bit/
[2]: https://unix.stackexchange.com/questions/191940/difference-between-owner-root-and-ruid-euid
~~~


