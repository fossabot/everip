# EVER/IP(R)
The EVER/IP Suite

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

## Trademark Notice
connectFree, the connectFree logo, EVER and EVER/IP are registered trademarks of connectFree Corporation in Japan and other countries. connectFree trademarks and branding may not be used without the express written permission of connectFree.

## License and Copyright
Copyright (c) 2017 kristopher tate & connectFree Corporation.

This project may be licensed under the terms of the GNU AFFERO General Public License version 3. Corporate and Academic licensing terms are also available. Please contact <licensing@connectfree.co.jp> for details.
