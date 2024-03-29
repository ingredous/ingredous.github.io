---
layout: post
title: Hijacking Over 100k GoDaddy Websites 
tags: [Research]
author: mqt @ Ingredous Labs
comment: true
---

# Summary
GoDaddy is a well-known domain registrar which also offers various complementary services such as hosting and website building. One service, in particular, is the [Website Builder](https://www.godaddy.com/en-uk/websites/website-builder) which allows anyone to build and publish a website regardless of their technical ability. As typical with these services, they allow custom domains to be configured with the website.

Due to a misconfiguration, it was discovered that any domain hosting a website built using this service could be taken over. This required no prior knowledge about the victim nor any interaction, but rather publishing your website using the target’s domain name thus overwriting the existing configuration as there was no validation performed.

Using various historical DNS data sources, it was roughly estimated that over 100,000 websites were susceptible to this vulnerability.

# Impact
The impact is pretty much identical to a typical subdomain takeover with some caveats as GoDaddy doesn’t appear to allow the user to access server-side logs. An attacker would still be able to take several different avenues:

- Serving malicious Javascript which could be leveraged to access cookies scoped to the parent domain (however in this case only cookies missing the HttpOnly flag), bypassing CORS whitelisting, and much more.

- Serving phishing content to visitors.

# Deep Dive
**Disclaimer:** _Anything mentioned in this section regarding how GoDaddy’s web hosting works under the hood is simply an assumption as GoDaddy did not share any information._

When a website is published using the website builder, it is hosted using GoDaddy’s shared web-hosting service. Like typical shared web-hosting services, virtual hosting is used thus granting the ability for a single webserver to host multiple websites. In order to route the end-user to the correct website, the value of the `Host` header found in the HTTP request is used.

One interesting thing that was discovered during the investigation process was that any IP Address belonging to the shared web hosting service could be used to serve the contents of any website built using the website builder.

To help illustrate this fact, we can take an example subdomain such as `shop.lumby.cyou`. When resolving the subdomain, we see that it points to `198.71.232.11` which is one of the IP Addresses used by GoDaddy’s shared web hosting service.


```
⇒ dig shop.lumby.cyou +short 
198.71.232.11
```

However, if we try accessing the site using a different IP Address used by GoDaddy’s shared web-hosting service such as `72.167.191.83`, it is still able to serve the contents of our site despite it being a completely different web-server:

```
⇒ curl 'http://72.167.191.83' -H 'Host: shop.lumby.cyou -is | head -n 10

HTTP/1.1 200 OK
<redacted for sake of brevity>
Cache-Control: max-age=30
Content-Security-Policy: frame-ancestors 'self' godaddy.com test-godaddy.com
dev-godaddy.com *.godaddy.com *.test-godaddy.com *.dev-godaddy.com
content-type: text/html;charset=utf-8
Vary: Accept-Encoding
Content-Encoding: raw
Server: DPS/1.13.2
X-SiteId: 1000
Set-Cookie: dps_site_id=1000; path=/
<redacted for sake of brevity>
```

This behavior itself is not strange but most likely done for a legitimate reason which is fault tolerance. The virtual hosting settings are replicated across each web server in case one goes down, another could act as a stand-in without risking the loss of customer’s data.

The reason this behavior was mentioned will be circled back to at the end of this section as it was vital for widespread exploitation.

Now to move onto the exploitation process.

When connecting a custom domain to the website builder, there will be a prompt that will ask for the domain:

![Screenshot]({{ site.baseurl }}/images/posts/2020/godaddy/godaddy-1.png)

At this stage an attacker would input a domain that is already pointing to GoDaddy’s shared web hosting services. If you’re wondering how an attacker would know which domains point to this service, it’s fairly simple. An attacker could go through this flow using a legitimate domain and on the next prompt, GoDaddy will provide the IP Address for which the DNS Record needs to be set to:

![Screenshot]({{ site.baseurl }}/images/posts/2020/godaddy/godaddy-2.png)

The attacker could repeat this flow a few times and eventually end up with a list of IP Addresses. This list could then be cross-referenced against various passive DNS resources to eventually end up with a catalog of domains.

Finally, after clicking through a few confirmation prompts, the attacker can visit the victim’s domain and observe that instead of the victim’s website being served, it is in fact the attacker’s.

An inadvertent side-effect was also discovered, if the attacker disconnects the victim’s domain from the attacker’s site after connecting it, the victim’s domain will enter a ‘nulled’ state as it appears the virtual hosting settings were overwritten and thus won’t serve their original website. To fix this, the victim will need to re-connect their domain or reach out to GoDaddy for further assistance.

Lastly, to conclude this section, we mentioned earlier that it was interesting that GoDaddy replicates the virtual hosting settings across all the webservers. This behavior is what allowed this misconfiguration to be so widespread. In the case where the replication behavior didn’t occur, an attacker would only be able to target domains that were hosted on the same shared web hosting server. While this itself wouldn’t be enough to stop an attacker from wreaking havoc, it wouldn't have made it as easy as it was to target practically any domain using GoDaddy's shared web hosting.

To see this in action, please watch the following proof of concept video. The left browser is the victim, while the right is simulating the attacker. 

[![GoDaddy Takeover PoC](https://res.cloudinary.com/marcomontalbano/image/upload/v1653519639/video_to_markdown/images/google-drive--1vd029qPskbZAZZTe-sO3QU7Ic7GSA-Cw-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://drive.google.com/file/d/1vd029qPskbZAZZTe-sO3QU7Ic7GSA-Cw/view "GoDaddy Takeover PoC")

# Credits
- [Jonathan Cran](https://twitter.com/jcran)
- [Shpend Kurtishaj](https://twitter.com/shpendk)
- [Maxim Gofnung](https://github.com/m-q-t)

# Timeline
- **17/03/2022** - Vulnerability discovered and report is submitted to GoDaddy’s Vulnerability Disclosure Program.

- **18/03/2022** - GoDaddy confirms they received the vulnerability and are investigating.

- **30/03/2022** - GoDaddy verifies that the vulnerability has been patched.

