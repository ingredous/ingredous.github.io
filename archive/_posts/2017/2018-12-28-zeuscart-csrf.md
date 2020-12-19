---
layout: post
title:	"Zeus Cart 4.0 CSRF Deactivate Customer Accounts"
date:	2018-12-28 03:00:00
categories:
    - notes
tags:
    - bug_hunting
    - vuln_writeup
---
<head>
	<title> Zeus Cart 4.0 CSRF Deactivate Customer Accounts </title>
</head>
![Screenshot]({{ site.baseurl }}/images/posts/2017/zeus-cart/logo.png)


# i. Introduction

Zeus Cart in general, is a PHP Shopping Cart. As of today, ZeusCart is nearly five years old, though it is still a great application for learning how to find bugs.

As with many shopping cart software, Zeus Cart is riddled with bugs. While practicing my bug hunting technique, I managed to find a CSRF, which allowed an attacker to disable customer accounts.

Once a customer account is disabled, it tells the customer that they have an invalid password, instead of letting them know they were banned.

# ii. Summary

According to OWASP, Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.

In basic terms, once an application has a cookie set in the user's browser, the browser will automatically submit the cookie to the applicatoin in every request. Which means if an attacker creates a HTML form that is auto submitted when a user clicks on it, they will be able to submit actions on behalf of the user.

To prevent CSRF, an application can use tokens. The application will issue a token on every action in the request. The token usually lives in a hidden input in the HTML. Therefore when the user submits a form, the application makes sure the token matches what was issued on the HTML.

# iii. Exploiting Zeus Cart

Once in the admin panel, under Customers, we are able to see all the registered customers.

![Screenshot]({{ site.baseurl }}/images/posts/2017/zeus-cart/customers.png)

When clicking the "Active" button under the Status column, and intercepting the request we can see:

![Screenshot]({{ site.baseurl }}/images/posts/2017/zeus-cart/request.png)

It is sending a GET request to disable an account with the ID of 1. Which we can infer is the first customer registered in the database.

As you may notice, in the request there is no parameter that validates any sort of tokens.

To abuse this, an attacker can create an HTML page that looks blank, but when the admin clicks on the page, it will send a GET request which in turn will deactivate an account.

From what seems a blank page, there is actually a request going on in the background.

![Screenshot]({{ site.baseurl }}/images/posts/2017/zeus-cart/blank.png)

We can see what's going on by viewing the source.

![Screenshot]({{ site.baseurl }}/images/posts/2017/zeus-cart/source.png)

As we can see, the page create a request by trying to fetch an image, and executes the request in the background.

You can view the PoC on: https://www.exploit-db.com/exploits/46027

Here it is in action:

![Screenshot]({{ site.baseurl }}/images/posts/2017/zeus-cart/csrf.gif)

## https://www.exploit-db.com/exploits/46027

# iv. Conclusion

In conclusion, Zeus Cart is a great way to practice hunting, and building your foundation. Though keep in mind, the software is reaching it's sixth year since it has last been updated. Which means today, applications are more secure as new techniques and methods have been developed. With all that in mind, developers tend to make mistakes and overlook certain functions of an application. Even today the same bugs found in this six year old software, are found on some of the biggest websites.


Thank you for reading.

~~~
Sources:
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
~~~
