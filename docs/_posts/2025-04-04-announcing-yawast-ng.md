---
layout: post
title:  "Announcing yawast-ng"
date:   2025-04-04 11:57:00 -0400
author: 'Adam Caudill'
---

YAWAST is back! Or more specifically, yawast-ng has arrived. After a years-long pause, YAWAST is now yawast-ng, and back in active development.

This project was created as a way to make penetration tests faster and more efficient, especially that first day of testing. Enabling testers to gain as much information as possible, as fast as possible. Why start at a walk, when you can go straight to a running start?

With a large number of [checks performed](https://numorian.github.io/yawast-ng/checks/), yawast-ng provides both actionable findings and useful insights into the target and its security posture. This provides the most efficient start possible.

## Why the new name?

 Details will be shared in the future, but yawast-ng will be moving to a more expansive set of goals than YAWAST had, and in the process, may introduce breaking changes compared to what YAWAST did; we don’t want to break things for those that  are still using YAWAST.
 
 As such, yawast-ng has a new name, including on [PyPi](https://pypi.org/project/yawast-ng/) and [Docker](https://hub.docker.com/r/adcaudill/yawast-ng).
 
 Due to the importance of stable output, the one thing that we will commit to not introducing any breaking changes to the JSON output (via the `--output` parameter).
 
## Why Now?

[Numorian](https://numorian.com), a security and AI consulting company, has been generous enough to support the renewed development efforts, both to improve their own services and as a way of giving back to the community. Numorian and I both see the value of this project, both in the value it offers today, and the promise it holds for the future.
 
## Available Now
 
 The first stable release of yawast-ng, v0.12.1, is available now at the links above, and has been updated to support the recent versions of Python. Due to the somewhat complex set of requirements, and broad cross-platform support, the Docker image is likely the easiest option.
 
## Questions & Support 

If you have any questions, or run into any issues, please don’t hesitate to [open an issue](https://github.com/Numorian/yawast-ng/issues/new).
