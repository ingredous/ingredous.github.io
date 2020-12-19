---
layout: post
title:	"Lazy Writeup"
date:	2018-09-11 03:01:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - hackthebox
---
<head>
	<title> Lazy Writeup | HackTheBox </title>
</head>

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/logo.png)

## i. Port Scan

Using nmap to scan the ports:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/portscan.png)

`Ports 80 (http) & 22 (ssh) are open.`

## ii. Enumeration

Browsing to the host on port 80:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/http.png)

We then register an account, and are automatically logged in:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/slime.png)

If we reload the page and intercept the request with Burp, we see a interesting cookie:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/request.png)

Modifying the cookie and resubmitting the page:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/modified.png)

An interesting error occurs:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/invalid.png)

Due to the error, we see that the website is vulnerable to an Oracle Padding Attack.

~~~
For more information on how the attack works:
https://www.owasp.org/index.php/Testing_for_Padding_Oracle_(OTG-CRYPST-002)
https://pentesterlab.com/exercises/padding_oracle
~~~

PadBuster is a tool in which can automate Oracle Padding Attacks.

~~~
https://github.com/GDSSecurity/PadBuster
~~~

We can use PadBuster to decrypt the cookie to see the format it is in:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/padcommand.png)

~~~
$ perl padbuster.pl [URL] [cookie value] [blocks] --cookies [full cookie]

blocks is usually 8 or 16. in order to find out what they mean, read the sources above.
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/format.png)

~~~
The cookie was decoded and the format is user=$USERNAME
~~~

Then use Padbuster again to encrypt the cookie in the format we need: `user=admin`

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/padcommand2.png)

~~~
$ perl padbuster.pl [URL] [cookie value] [blocks] --cookies [full cookie] --encoding 0 -plaintext user=admin
~~~

After Padbuster is finished, we can modify the request in Burp and insert our new value:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/padresults.png)

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/modifyrequest.png)

Reloading the page:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/admin.png)


Awesome, we are now logged in as admin. 

We see that there is a message with an SSH key, clicking on the link:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/sshkey.png)

After downloading the key to our system, we need a username to go alone with the key. If we look at the URL, we see:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/sshmitsos.png)

Then we need to fix the permissions on the SSH key, and use it to login:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/ssh.png)

~~~
$ chmod 600 id_rsa
$ ssh -i id_rsa mitsos@10.10.10.18
~~~

## iii.Privilege Escalation

After enumerating the system, we find some interesting files in mitsos' home directory:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/home.png)

Looking at backup's information, we see that it is a SUID binary (which means whenever a user runs it, it runs as the owner of the file)

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/backup.png)

If we run ./backup, we see that /etc/shadow gets printed out:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/shadow.png)

Going to save you some time, `the hashes are not crackable.`

In order to see exactly what ./backup does we can use GDB:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/gdb.png)

The command that ./backup is running is `cat /etc/shadow`

Which means that `cat` is being run as root because when we execute a SUID binary we run it as the rights of the owner of the file (root)

The way that the Linux Path works is that it checks each directory in $PATH to find the executable for the command being run:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/path.png)

~~~
First it looks for cat in /usr/local/sbin, then /usr/local/bin, until /usr/local/games
~~~

To check where cat is located, we can use `which`:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/bincat.png)

So `cat` lives in `/bin`, as mentioned earlier, Linux goes in order of the $PATH. If we add a custom directory to the beginning of the path and have an executable named cat there, it will run that.

Editing the $PATH and adding a custom directory:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/editpath.png)

Now Linux will check /home/mitsos whenever a command is run.

Now we will create a simple bash script named cat,  when run it will spawn a new shell.

`Don't forget to give cat executable permissions!`

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/cat.png)

The reason we have the interpreter on top of the file is so when Linux runs a file it can interpret what type of file is based on the interpreter, rather than using an extension (such as .sh), which would mess up our privilege escalation.

~~~
https://stackoverflow.com/questions/2429511/why-do-people-write-the-usr-bin-env-python-shebang-on-the-first-line-of-a-pyt
~~~

`NOTE: I'm using sh because bash drops EUID (Effective User ID).`

~~~
When running a file with SUID bits, your EUID becomes the ID of the owner of the file, which in this case is root.

So when we run backup, it will execute cat as root, which in turn will spawn us a shell. Though when a bash shell is spawned it strips the EUID, though SH doesn't.

More information:
https://unix.stackexchange.com/questions/451048/from-which-version-does-bash-drop-privileges
~~~

`You can also use a python script if you don't want to deal with the permissions`

Now when we execute backup again, we are running it as root, so root executes our cat and gives us a new shell:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/euidroot.png)

If we look at our UID we see that we are still the same user, though looking at our EUID we see that we are root.

Now when running commands, they are ran as root:

![Screenshot]({{ site.baseurl }}/images/posts/2017/lazy/root.png)

## iv. Conclusion

I liked this box a lot. The reason being, is that it's a great box for learning Linux fundamentals. With this box, you learn how SSH keys work, how the Linux PATH works, and how SUID binaries work.

Also there is the Padding Oracle Attack, which might be useful... some day.

Overall, great learning box.

Thanks for reading.

~~~
Sources / Links:

[0]: https://www.owasp.org/index.php/Testing_for_Padding_Oracle_(OTG-CRYPST-002)
[1]: https://pentesterlab.com/exercises/padding_oracle
~~~




