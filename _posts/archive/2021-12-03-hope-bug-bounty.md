---
layout: post
title: '"Hope Bug Bounty"'
tags: [Personal]
author: Ingredous Labs
comment: true
---

While skimming through the book "A Guide To Chess Improvement" by Dan Heisman, a particular section caught my eye which was **"Hope Chess"**.  

Heisman defines "Hope Chess' as the following:

```
- Making a move without analyzing whether you can safely meet any forcing reply.
- Seeing a good move and not looking for a better one.
- Not looking for all your opponent's threats from his previous move.
```

This term struck a chord within me as it forced me to come to the realization that I've been treating bug bounty as essentially "Hope Bug Bounty". While bug bounty and chess are two entirely different subjects, they both share a lot of the same principles.

Specifically what I mean by "Hope Bug Bounty" is where one fails to take the time and learn the inner workings of the application and its respective developer's habits. Instead one finds themselves spraying and praying various payloads and trying several low-hanging fruit techniques before calling it a day and moving on to the next application. Rather than trying to grasp a proficient understanding of how a specific endpoint should behave, one just sees the parameters that may be reflected in the source or passed to a database. While in some scenarios this kind of approach works, however the majority of time it tends to cause one to miss vast amounts of bugs.

To conclude this post, I'll leave a paraphrased excerpt in which my close friend and mentor [Shpend K](https://twitter.com/shpendk) mentioned while we were discussing a similar topic:

> One's goal when testing an application is to obtain a level of understanding of how the application works to the point where they can essentially become a junior developer.

Thanks for reading.