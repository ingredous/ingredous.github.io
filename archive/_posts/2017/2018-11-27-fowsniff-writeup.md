---
layout: post
title:	"Fowsniff Writeup"
date:	2018-11-27 03:00:00
categories:
    - writeups
tags:
    - ctf
    - boot2root
    - vulnhub
---
<head>
	<title> Fowsniff Writeup | Vulnhub </title>
</head>
![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/logo.png)

## i. Port Scan

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/ports.png)

## ii. Enumeration

Starting off with port 80, browsing to the host:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/http.png)

Looks like a static HTML page...

Scrolling further down on the page, there is a note:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/note.png)


Finding the fowsniff twitter (@fowsniffcorp), there is a stickied tweet:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/tweet.png)

Following the Pastebin link, we can see that there was a data breach, and the passwords were dumped:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/passwords.png)

The passwords are in MD5 format, either using hashkiller (`https://hashkiller.co.uk/md5-decrypter.aspx`) or hashcat we can decrypt the passwords:

~~~
 8a28a94a588a95b80163709ab4313aa4 MD5 : mailcall
 ae1644dac5b77c0cf51e0d26ad6d7e56 MD5 : bilbo101
 1dc352435fecca338acfd4be10984009 MD5 : apples01
 19f5af754c31f1e2651edde9250d69bb MD5 : skyler22
 90dc16d47114aa13671c697fd506cf26 MD5 : scoobydoo2
 a92b8a29ef1183192e3d35187e0cfabd [Not found]
 0e9588cb62f4b6f27e33d449e2ba0b3b MD5 : carp4ever
 4d6e42f56e127803285a0a7649b5ab11 MD5 : orlando12
 f7fd98d380735e859f8b2ffbbede5a7e MD5 : 07011972 
 ~~~

 Now that we have the list of passwords and usernames, we can attempt to start cracking pop3 using `hydra`.

 First we have a txt with all the usernames:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/users.png)

And the passwords in another file:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/pass.png)

```
It takes a while to try every single username & password due to the way you have to authenticate with POP3. So it is easier & faster to just bruteforce.
```

Starting hydra:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/hydra.png)

```
hydra -L users.txt -P pass.txt -f {IP} pop3

-L ~ username wordlist
-P ~ password wordlist
-f ~ stop cracking when valid user is found
```

We can see that a valid user is found:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/validuser.png)

`Attempting to reuse the user's credentials for SSH does not work, so let's see if we can enumerate their mailbox`

Authenticating with the mail server:
![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/pop3.png)

Using the `list` command to see if there any messages.

We can see there are two messages, we can use `retr [id]` to read the mail:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/mail1.png)

Awesome, we got an SSH password!

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/sshpass.png)

Attempting to use SSH password with Seina:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/sshfail.png)

Hmm... if we look at the e-mail again, we can see this email was sent to multiple users:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/multipleusers.png)

So we can use hydra with our username wordlist earlier and the new password to see if we can find any valid users.

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/hydrassh.png)

```
The reason we use a lowercase p instead of the uppercase as earlier, because the uppercase is for a wordlist, while lowercase is for a single string
```

Almost instantly, hydra finishes and we find a valid user:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/baksteen.png)

Trying to login with SSH:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/sshauth.png)


iii. Privilege Escalation

So while enumerating the system, it looked like it was fresh out of box, with the exception of the mail server being configured (Dovecot).

The Dovecot had no exploits (as it's a newer version)

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/dovecot.png)


While digging some more, we can find an interesting directory in the /opt folder:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/cube.png)

The directory looks world-writeable as well.

Enumerating inside the directory we find a script:

The contents of the script look similar to the MOTD we saw when logging in with SSH:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/script.png)

A huge hint was the printf, looks like MOTD might be calling it.

To confirm our suspicion, we can check out the directory in which MOTD files live: `/etc/update-motd.d`


Listing the files we can see there are multiple files:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/motd.png)

Starting off with the header file:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/header.png)

Interesting, on `line 31` we can see the file calling the script! 

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/callscript.png)

The way the MOTD (Message of the Day Works) is when a user logs into the box, they will be presented a message.

On `line 29`, we can see what the default message usually is. (Commented out)

So with this information in mind, next time we login, the MOTD will call the script. 

Going back to the script, we can insert a reverse shell to connect back to us when the script is called.

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/reverse.png)

I am using the nc reverse shell one-liner, because we can see that nc is installed on the box:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/nc.png)

Now let's setup a listener, and login to the box again via SSH:

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/root.png)

As soon as we authenticate, MOTD launches and calls the script. (MOTD is running as root, so a high privileged shell comes back.)

![Screenshot]({{ site.baseurl }}/images/posts/2017/fowsniff/flag.png)

iv. Conclusion

I really enjoyed this box personally for various reasons. The first being that the box is sort of realistic by breaking the fourth wall. Dumps happen everyday, and it is not rare you will find the information on Pastebin.That made it a really enjoyable way, instead of the default exploit -> root

Second, the priv esc was very unique. I have never ran into this sort of priv esc before and it taught me more about how MOTD works, and where the files for it live.

Overall, this box was really enjoyable, try it here yourself: https://www.vulnhub.com/entry/fowsniff-1,262


Sources/Links:
~~~
[0]: https://tools.kali.org/password-attacks/hydra
[1]: https://hashkiller.co.uk/md5-decrypter.aspx
[2]: https://www.networkworld.com/article/3219736/linux/how-to-use-the-motd-file-to-get-linux-users-to-pay-attention.html
[2]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~


