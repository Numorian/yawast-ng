---
layout: default
title: FAQs
permalink: /faq/
---

This page is a collection of common questions about yawast-ng.

### Can I use yawast-ng commercially?

This can mean one of two things, which will be answered separately:

*Can I use yawast-ng as part of paid work?*

Absolutely. That's really what it's for. The goal of yawast-ng is to make professionals more productive and allow them to spend more time on manual testing, instead of spending so much time on things that could be automated.

*Can I integrate yawast-ng into a commercial product?*

This is a complicated question. While yawast-ng itself is [licensed](https://github.com/Numorian/yawast-ng/blob/master/LICENSE) under the MIT license which is very permissive, yawast-ng also uses a number of third-party libraries which have various [OSI](https://opensource.org/) licenses. These licenses have different terms which may impact you, and may limit how you can integrate yawast-ng. Given the number of licenses involved, we do not take a position on your ability to integrate yawast-ng into a commercial product. If this is your intention, you will need to review all dependencies, and likely consult with an attorney to determine what you are and aren't able to do within the various licenses.

### What does the name mean?

When this project was started, the original name was "Yet Another Web Application Security Tool" - as the project became more serious, the name was changed to a recursive acronym, "YAWAST Antecedent Web Application Security Toolkit." The current name better reflects the role of the tool, and its place in the penetration tester's workflow. It's meant to be a first step, to come before the serious manual work, and provide information to allow a tester to be up and running more quickly. The tests that are performed are based on that goal, as well as the availability and complexity of tests in other tools. If another common tool can do a given task better, it won't be done here.

YAWAST was actively developed from 2013 to 2020; in 2025 the project was relaunched as yawast-ng, representing the next generation of the project. With this relaunch of the project, it was given new focus, more support, and a broader mission.

### Why did YAWAST change from Ruby to Python?

YAWAST was started in 2013, and at the time Ruby was a preferred language in the security community, at least in part due to Metasploit Framework being written in Ruby. Fast forward six years to 2019, and Ruby had fallen out of favor in the community. In a poll of those in the community that are likely to contribute to a project like YAWAST, we found that the vast majority were more likely to contribute if the application was written in Python; in fact, Ruby scored as the language least likely to lead people to contribute.

Based on the popularity of Python and the poll indicating that being written in Python would make contributions more likely, the decision was made to completely rewrite YAWAST. With the rewrite, the goal was to encourage lead more participation and provide a healthier future for the project.

### Didn't YAWAST used to have a Windows version?

Yes, though not anymore. Due to an increasingly complex chain of dependencies, and complications making certain features work on Windows, the platform is not currently supported.

### Does yawast-ng receive financial support?

Yes; yawast-ng is directly supported by [Numorian](https://numorian.com), a security and AI consulting company.
