---
layout: post
title: OAuth Research Notes 
tags: [Research Development]
author: mqt @ Ingredous Labs
comment: true
---

## Preface 
After reading `So Good They Can't Ignore You` by Cal Newport, I was enthralled by the topic of `Little Bets`.

Little Bets are defined as:

> bite-sized, carefully chosen projects that take no more than a few months, give you valuable feedback, and help you to determine your next steps. You don't need to commit to a project that will determine your work life for the next few years. Take on small projects and continuously adapt.

[Source](https://deepstash.com/idea/60897/take-on-little-bets)

In the book, the author gives an example of a recently published paper which in his community was gaining a lot of traction. While people were able to adequately explain the topic of the paper at a high level, very few understood how it worked under the hood. The author chose to spend an hour a day learning the paper over the period of two weeks until they eventually accomplished an expert level of understanding and even going as far to discover a mistake made in the paper.

With that being said, I wanted to replicate the author's experience and as such I chose OAuth as my research project. The two main reasons why I chose OAuth as the research topic is due to how broad the topic is and its increasing popularity in the recent years. Rather than researching some novel attack techniques, I first needed to take a step back and actually do a deep dive and understand what OAuth is and how it works. 

## Notes

After spending a few weeks studying the topic across different sources, I compiled my notes into an easily digestible Gitbook Notebook which can be found at:

[https://mqt.gitbook.io/oauth-research/](https://mqt.gitbook.io/oauth-research/)

The intended audience of the notebook is for everyone regardless if they're a developer or a pentester. The notes were designed in such a way that if you blank on a specific OAuth topic, you can quickly revisit the notes and read a high level overview. Furthermore included in the notes are several proof of concepts which demonstrate various vulnerabilities that could be found in an OAuth implementation.

## Conclusion

Thanks for reading and please reach out if you have any questions and/or suggestions.