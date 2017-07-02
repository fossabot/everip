# EVER/IP(R)
The Elastic Versatile Encrypted Relay for IP (EVER/IP) Networking Suite

[![Build Status](https://travis-ci.org/connectFree/everip.svg?branch=master)](https://travis-ci.org/connectFree/everip)
[![FOSSA Status](https://app.fossa.io/api/projects/undefined.svg?type=small)](https://app.fossa.io/projects/undefined?ref=badge_small)

![EVER/IP Logo](https://raw.githubusercontent.com/connectfree/everip/master/everip_logo.png)

## What is EVER/IP?

EVER/IP is a new way to think about building the Internet. When the Internet was first developed in the 1980s, there was limited computational power to route millions of messages per second. The solution that the godfathers of the Internet introduced was a prefix-based memory-bound routing table design that requires very expensive custom ASIC and memory to operate at scale.

Fast-forward three decades, EVER/IP is the first kind of routing software that does not require memory expensive routing tables, but instead uses the CPU to calculate forwarding direction based entirely on local information.

Being entirely local information driven, there is no need for expensive ISPs and Providers, thus reducing the cost of communication for people and things alike.

Thanks in part to the iPhone(r)<sup>(1)</sup> and other smartphones of its generation, the computing power that we have in our pocket is incredible. EVER/IP aims to unleash this power, bringing-down the cost of communications worldwide and beyond. 

Microsoft helped take us from the mainframe era with micro-software. We aim to take humanity into an era from Internet eXchanges to Micro Internet eXchanges (MIXes). Welcome to the MicroISPb" era.

<sup>(1)</sup> iPhone(R) is a trademark of Apple Inc., registered in the U.S. and other countries.

## Frequently Asked Questions
EVER/IP is a relatively new technology and you might have some questions about it. Head on over to our [FAQ Document](docs/FAQ.md) for more information.

## Screenshots
Start-up:

![EVER/IP Screenshot 1](https://raw.githubusercontent.com/connectfree/everip/master/docs/everip_screenshot1.png)

Main-Menu:

![EVER/IP Screenshot 2](https://raw.githubusercontent.com/connectfree/everip/master/docs/everip_screenshot2.png)

FieldIX(TM) Peers and Conduits:

![EVER/IP Screenshot 3](https://raw.githubusercontent.com/connectfree/everip/master/docs/everip_screenshot3.png)

## Layers

| Layer     | Sub-Layer   | Purpose                                    |
|----------|----------|------------------------------------------------|
| geofront      | `conduit` | Provides interface to physical realworld devices             |
| centraldogma      | `relaymap` | Provides relay functionality between conduits             |
| centraldogma      | `cmdcenter` | Commands layer-2 control plane             |
| centraldogma      | `manager` | Manages layer-3 sessions             |
| magi      | `eventdriver` | Shuttles events between layers             |
| magi      | `starfinder` | Searches and monitors peers in field network             |
| misato      | `cmd` | Command interface for operators             |
| misato      | `everip` | Initialization engine             |
| misato      | `module` | Module management routines             |
| misato      | `ui` | UI management routines             |
| ritsuko      | `addr` | Authenticated IP routines             |
| ritsuko      | `bencode` | Bencode routines             |
| ritsuko      | `log` | Log and debug routines             |
| ritsuko      | `mrpinger` | Ping routines and timers             |
| ritsuko      | `net_*` | Platform network event handlers             |
| terminaldogma      | `terminaldogma` | Interface connecting centraldogma to lowest layers of the device            |
| terminaldogma      | `tun_*` | Platform specific tunnel interfaces            |

## Modules

| Module     | Kind   | Purpose                                    |
|----------|----------|------------------------------------------------|
| eth      | `conduit` | Implements the ETH conduit for EVER/IP over Layer-2            |
| udp      | `conduit` | Implements the UDP conduit for EVER/IP over Layer-3             |
| dcmd      | `app` | Interactive debug command suite for EVER/IP             |
| stdio      | `ui` | Forms the bridge between the terminal and EVER/IP             |


## Trademark Notice
connectFree, the connectFree logo, EVER and EVER/IP are registered trademarks of connectFree Corporation in Japan and other countries. connectFree trademarks and branding may not be used without the express written permission of connectFree.

## License and Copyright
Copyright (c) 2017 kristopher tate & connectFree Corporation.

This project may be licensed under the terms of the GNU AFFERO General Public License version 3. Corporate and Academic licensing terms are also available. Please contact <licensing@connectfree.co.jp> for details.


[![FOSSA Status](https://app.fossa.io/api/projects/undefined.svg?type=large)](https://app.fossa.io/projects/undefined?ref=badge_large)