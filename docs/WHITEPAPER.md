# Whitepaper: The EVER/IP Networking Suite

EVER/IP is a new way to think about building the Internet by redefining how packets are created and routed.

This whitepaper aims to describe and outline the EVER/IP Networking Suite.

## Table of Contents

1. [Introduction](#introduction)
2. [Related Work](#related-work)
3. [Design Goals](#design-goals)
4. [Implications](#implications)
5. [Feature Set](#feature-set)
6. [Routing Engine](#routing-engine)
7. [Encryption Engine](#encryption-engine)
8. [Conclusion](#conclusion)

## Introduction

The Internet may be the most important discovery and invention of mankind. Its explosive growth has fuelled countless industries and its significance is perhaps only second to the discovery of the personal computer.

In the 1980s when the Internet was first developed, computers were of limited computational resource. Therefore it was decided that in order to effectively route millions of packets per second, trade-offs had to be made and thus the Internet was split into two "levels":

1. A memory-bound lower level to be concerned with transporting data packets between neighbouring network nodes (called IMPs, known today as routers)
2. A higher level to be concerned with various end-to-end aspects of the data transmission (known today as TCP/IP).

The immediate lack of computational power has forced the implementation of the Internet to become memory-bound and thus its core infrastructure requires tremendous dedication, resource and power. The complexity in managing this core infrastructure has become a major industry, keeping the cost of communication relatively high and core growth relatively low.

In this paper, we introduce a solution for a better Internet with the Elastic Versatile Encrypted Relay for IP (EVER/IP) Networking Suite. EVER/IP is routing software that does not incorporate expensive memory routing tables and instead uses the CPU to calculate forwarding direction based entirely on local information.

This is finally possible due greatly in part to the iPhone® and other smartphones of its generation that have pushed for smaller, more efficient, more powerful processors and the FABs such as TSMC in Taiwan who have raced to scale production. EVER/IP aims to unleash this power, bringing-down the cost of communications worldwide and beyond.


## Related Work

In the wireless connectivity field, self-configuring protocols such as BATMAN [1], HSLS [2] and OLSR [3] are well known and deployed. These protocols try to relieve the configuration burden at the edge, but only by centralising configuration and management. Cisco Meraki [4] is a commercial solution that aims to help network administrators by keeping configuration in the cloud, but these solutions simply mask the core problems with more configuration.

Experimental solutions such as VRR [5], CJDNS [6] and SAFE Network [7] use Distributed Hash Tables (DHTs) to improve the scalability of routing. However, such DHT-based solutions assume that the nodes exist in a Euclidean space and rely an XOR metric. On the contrary, it has been shown that Euclidean spaces are not well suited to represent Internet nodes [8] and in our implementation EVER/IP assumes nodes interact within an arbitrary connectivity graph.


## Design Goals

1. Create an Internet that could work on multiple planets.
2. Create an Internet without dedicated core routing infrastructure.
3. Maintain backwards compatibility with existing IP products and solutions.
4. Provide a solution that is both secure and elastic, removing the need for network administrators.

## Implications

The implications of our work is that if we succeed, the cost for communication will greatly drop. We see this as a boon for the global economy and perhaps the start of a multi-planetary economy. The current Internet is too centralised for its own good and it requires the help of large corporations to mediate.

Let it be known that we are not against telecommunication corporations. Instead, we see this software as becoming a great help to their core mission. Telecommunication corporations may become more lean and thus profit margins will increase.

Our work focuses on the Internet of Things and building a network of things, instead of simply placing Things on the Internet. Many corporations (especially in Japan) who produce social infrastructure technologies and solutions cannot pay for monthly Internet access per device. Their business models require that any service or part must be incorporated into its Bill of Materials (BOM). We see a huge gap in this market that EVER/IP is poised to take part in. It is our great hope that EVER/IP helps to create a new connected economy, both on Earth and beyond.


## Feature Set

1. Each device is assigned a cryptographically signed and authenticated public and private key.
2. Said assigned public/private key is used to generate a cryptographic hash that will represent the node's IP address.
3. All communications are encrypted at OSI Layer-3, so there is no need to integrate TLS into the application. (TLS can still be used if required)
4. Packets are routed over any media, so long as another EVER/IP state machine is on the other side. We have implementations for Layer-2 (802.3 Ethernet/802.11 WiFi/Fibre) and UDP connectivity at Layer-3.
5. Existing applications just work: EVER/IP reports itself to the Operating System as a VPN.
6. No need for network administrators: network configuration is instant and autonomous.

## Routing Engine

![Traditional Routing](/docs/traditional-routing.png)

![MPLS/CJDNS Routing](/docs/label-based-routing.png)

![EVER/IP Routing](/docs/everip-based-routing.png)

## Encryption Engine

## Conclusion


[1]: https://en.wikipedia.org/wiki/B.A.T.M.A.N.
[2]: https://en.wikipedia.org/wiki/Hazy_Sighted_Link_State_Routing_Protocol
[3]: https://en.wikipedia.org/wiki/Optimized_Link_State_Routing_Protocol
[4]: https://meraki.cisco.com/
[5]: https://www.microsoft.com/en-us/research/publication/virtual-ring-routing-network-routing-inspired-dhts/
[6]: https://github.com/cjdelisle/cjdns
[7]: https://github.com/maidsafe
[8]: http://domino.research.ibm.com/library/cyberdig.nsf/papers/492D147FCCEA752C8525768F00535D8A
