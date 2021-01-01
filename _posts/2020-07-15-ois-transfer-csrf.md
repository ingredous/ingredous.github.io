---
layout: post
title: CVE-2020-35675
tags: [CVE-Writeup, CSRF]
author: Ingredous Labs
comment: true
---

```
Software Name: Online Invoicing System
Software Version: < 3.0
Software Developer: https://bigprof.com/
Link to Software: https://github.com/bigprof-software/online-invoicing-system
Vulnerability: Application Takeover via Cross Site Request Forgery
CVE ID: Pending
Pending
```

# Introduction

Online Invoicing System offers a functionality which allows an administrator to move the records of members across groups. The endpoint (admin/pageTransferOwnership.php), which is responsible for moving members across groups lacks CSRF protection thus resulting in an attacker being able to escalate their privileges to Administrator and effectively taking over the application by having the application's admin browse to an attacker controlled page which contains the specially crafted proof of concept.

# Exploitation Details

**PHP Version used throughout this writeup: PHP 7.4.8**

When browsing to `admin/pageTransferOwnership.php` with a user that has administrative privileges, the "Batch Transer of Ownership" functionality will be made available:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-csrf/batch.png)

As stated by the application, this functionality allows an administrator to:
> The batch transfer wizard allows you to transfer data records of one or all members of a group (the source group) to a member of another group (the destination member of the destination group)

After selecting the required dropdowns, an example of a successful request will look as follows:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-csrf/request.png)

Let's break down the above request to make it easier to understand:

~~~
sourceGroupID = The ID of the group you would like to be moving records from. 
sourceMemberID = The username of the member you would like to move records for. Using -1 means that all user records will be moved.
destinationGroupID = The ID of the group you would like to move records to.
moveMembers = If 1 that means it will move the member and their data to the group and not overrwrite any existing records in the destination group.
~~~

Something else you might notice in the request is that there appears to be no CSRF protecton such is in the form of a token (whether it be a parameter or cookie). Furthermore looking closely, we notice that the application does not utilize `Same Site Cookies` meaning this this endpoint is most likely vulnerable to Cross-Site Request Forgery.

However as shown in the request above in order for succesful exploitation to occur, an attacker would need to know the values of the following parameters:

~~~
sourceGroupID
destinationGroupID
~~~

After enumerating the application, it appears there is no concrete way for an attacker to retrieve the Group ID in which they are part of. Furthermore, it appears there is no way for the attacker to retrieve the Group ID of the Administrator's group either. While normally this could be seen as the nail in the coffin, there is a way around this.

An astute attacker would observe that on a fresh install, there are two groups which are created automatically with the following ID's:

~~~
Anonymous - 1
Admins - 2
~~~

Meaning that anytime a new custom group will be created, it will start from ID 3 and increment from there. Finally, the application does not allow the administrator to delete the pre-created groups meaning the ID of the Admin group will always result in 2.

With this in mind, an attacker is now aware of the `destinationGroupID` and will only need the `sourceGroupID` in which they are apart of in order to transfer their account to the Admin's group therefore granting themselves administrator privileges.

As mentioned earlier, this value will start from 3 and increment based on the number of custom groups the application has.

Since the endpoint is using a `GET` request to pass the information to the server, the following HTML snippet can be used:

~~~javascript
<img src="http://localhost/admin/pageTransferOwnership.php?sourceGroupID=3&sourceMemberID=attacker&destinationGroupID=2&destinationMemberID=&moveMembers=1&beginTransfer=1"></img>
~~~

Upon the application's administrator visiting a page which contains the above HTML, their browser will try to load the image by requesting the URL above. However instead of loading the image, the browser will follow the URL and trigger the vulnerability. The proof of concept above will attempt to move the records of a member whose username attacker from Group 3 to Group 2.

As mentioned before, the attacker is unaware of the group in which their user lives in. Using the snippet above is effectively playing Russian Roulette as the attacker will have to keep guessing their group. In order to have a good chance of this working, an attacker will need to be extremely lucky.

However instead of relying on luck, the attacker can utilize Javascript to leverage the following proof of concept:

~~~javascript
<script>
var i;
for (i = 3; i < 13; i++) {
    var x = document.createElement("IMG");
    x.setAttribute("src", "http://localhost/admin/pageTransferOwnership.php?sourceGroupID="+i+"&sourceMemberID=attacker&destinationGroupID=2&destinationMemberID=&moveMembers=1&beginTransfer=1");
} 
</script>
~~~

The above Javascript snippet will result in 10 iterations (3 -> 13) with each iteration creating a new image tag which sets the value of the `sourceGroupId` parameter to the current value of `i` in the iteration. In the end this will result in 10 image tags with each having a different value for the `sourceGroupID` parameter. In this example, 3-13 was used however in a real life scenario an attacker can create as many iterations as they would like. The reason the range starts at 3 is because it was confirmed earlier that any new custom groups start at that index.

Upon the application's administrator visiting this proof of concept, we can confirm that the requests are succesfully executing by taking a look at the browser's DevTools Network Tab:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ois-csrf/network.png)

As such, an attacker is able to host a specially crafted proof of concept that upon being visted by the application's administrator will move the attacker's user into the Admin's user group therefore effectively granting the attacker administrative privileges and allowing them to takeover the application.

# Proof of Concept

~~~html
<html>
<body>
<script>
var i;
for (i = 3; i < 13; i++) {
    var x = document.createElement("IMG");
    x.setAttribute("src", "http://localhost/admin/pageTransferOwnership.php?sourceGroupID="+i+"&sourceMemberID=attacker&destinationGroupID=2&destinationMemberID=&moveMembers=1&beginTransfer=1");
} 
</script>
</body>
</html>
~~~

**Replace above**:
- Range to suit your needs
- URL pointing to the vulnerable application
- Value of sourceMemberID with your username
