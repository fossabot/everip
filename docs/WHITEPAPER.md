# Whitepaper: The EVER/IP Networking Suite

EVER/IP is a new way to think about building the Internet by redefining how packets are created and routed.

This whitepaper aims to describe and outline the EVER/IP Networking Suite.

## Table of Contents

1. Introduction
2. Related Work
3. Design Goals
4. Implications
5. Feature Set
6. Routing Engine
7. Encryption Engine
8. Conclusion

## Introduction

The Internet may be the most important discovery and invention of mankind. Its explosive growth has fuelled countless industries and its significance is perhaps only second to the discovery of the personal computer.

In the 1980s when the Internet was first developed, computers were of limited computational resource. Therefore it was decided that in order to effectively route millions of packets per second, trade-offs had to be made and thus the Internet was split into two "levels":

1. A memory-bound lower level to be concerned with transporting data packets between neighbouring network nodes (called IMPs, known today as routers)
2. A higher level to be concerned with various end-to-end aspects of the data transmission (known today as TCP/IP).

The immediate lack of computational power has forced the implementation of the Internet to become memory-bound and thus its core infrastructure requires tremendous dedication, resource and power. The complexity in managing this core infrastructure has become a major industry, keeping the cost of communication relatively high and core growth relatively low.

In this paper, we introduce a solution for a better Internet with the Elastic Versatile Encrypted Relay for IP (EVER/IP) Networking Suite. EVER/IP is routing software that does not incorporate expensive memory routing tables and instead uses the CPU to calculate forwarding direction based entirely on local information.

This is finally possible due greatly in part to the iPhone® and other smartphones of its generation that have pushed for smaller, more efficient, more powerful processors and the FABs such as TSMC in Taiwan who have raced to scale production. EVER/IP aims to unleash this power, bringing-down the cost of communications worldwide and beyond.









