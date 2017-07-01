# Build Instructions

## Set-up your directory Structure

First, create a directory called ```everopen``` somewhere on your system.

Next, we need to ```cd``` into the ```everopen``` directory and clone everip and friends.

```
cd everopen
git clone https://github.com/connectFree/everip.git
git clone https://github.com/connectFree/libre.git
git clone https://github.com/connectFree/libsodium.git
```

## Build Each of the associative libraries

### libre

```
cd /path/to/everopen
cd libre
STATIC=1 USE_OPENSSL= make
```

### libsodium

```
cd /path/to/everopen
cd libsodium
./autogen.sh #requires automake
./configure --prefix=$PWD/../build_libsodium --disable-shared
make
makeinstall #this will only install to the base of everopen
```

## Build EVER/IP

**[A Friendly Notice]**
Building EVER/IP is fine for personal use only if you have obtained a license file.
If you do not have a license file, please contact <licensing@connectfree.co.jp> or our distributor network.
If you have not signed our CLA or otherwise do not have a license, your actions may infringe on our trademark.
**[/A Friendly Notice]**

```
cd /path/to/everopen
cd everip
SIGNED_CLA_LICENSE=1 LIBSODIUM_PATH=../build_libsodium USEGENDO=1 make
```

## Start EVER/IP

After building EVER/IP, the ```everip``` binary should be at the root of the build path.

Start ```everip``` with the following command:

```
cd /path/to/everopen
cd everip
sudo ./everip
```

You should get the following output on your terminal:

```
$ sudo ./everip
Password:

Starting connectFree(R) EVER/IP(R) for darwin/x86_64 [0.0.3]
Copyright 2016-2017 Kristopher Tate and connectFree Corporation.
All Rights Reserved. Protected by International Patent Treaties.
More information: select "Legal Information" from the main menu.

Local network address:  IPv4=en0:192.168.64.2 
activated caengine
UNLOCKING LICENSED EVER/IP(R) ADDRESS
fcXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX
listening on UDP socket: 0.0.0.0:1111
EVER/IP(R) is READY.


```

If you press ```enter``` on your keyboard, the following menu should appear:

```
[EVER/IP(R)][Main Menu]
  :crypto        c        Crypto-Authentication (CA) Engine
  :dht           d        DHT Database
  :legal                  Legal Information
  :main                   Main loop debug
  :memstat       m        Memory status
  :modules                Loaded Module List
  :net           n        Network Information
  :peers         p        Peers and Conduits
  :quit          q        Quit
  :sys           s        System Information
  :timers                 Timer debug
  :tree          t        Routing Tree Information
```

