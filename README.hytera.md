#Hytera "IP Multi Site Connect" Protocol  
Three main types of packets all UDP, each set at the repeater to run on a specific port.
* Networking - Exchange Information about other devices and service in the network
* Service - Voice and Data 
* RDAC - For remote diagnostic and control of Devices

##Service Packet
```
|------------------------------------------------------------------------------------------------------------------------------------------------|
|0                   1                   2                   3                   4                   5                   6                   7   | 
|0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
|------------------------------------------------------------------------------------------------------------------------------------------------|
|<4 BYTE><>      <><ASCI>        <sn><pt>1111<dt>    <---- AMBE+2 VOICE  ----> <--SYNC --> <---- AMBE+2 VOICE    ---->       <>  <gid ><sid >    |
|------------------------------------------------------------------------------------------------------------------------------------------------|
```


| Offset | Len | Format / Value          |Note               |
| ------ | ------  | --------------------|:----------------- |
|  00    |  2      |   ASCII "ZZZZ"      | Header            |
|  00    |  2      |   0-65535           | UDP Port Number   | 
|  04    |  1      |   0-255             | Sequence Number   | 
|  08    |  1      |   Num               | Packet Type       | 
|  09    |  3      |   ASCII "ZZZ"       | Special ASCII     |
|  16    |  2      |   ASCII             | Slot Number  (sn) |
|  18    |  2      |   ASCII             | Packet Type 2(pt) |
|  20    |  2      |   ASCII             | Flag always 1111  |
|  22    |  2      |   ASCII             | Data Type    (dt) |
|  26    |  13.5   |   RAW               | AMBE+2 Payload 1  |
|  38.5  |  6      |   RAW               | DMR Sync          |
|  44.5  |  13.5   |   RAW               | AMBE+2 Payload 2  |
|  62    |  1      |   Num               | Destination Type  |
|  64    |  3      |   Num 16bLE         | Destination Group |
|  67    |  3      |   Num 16bLE         | Source ID *Bug    |

####Header
Indicates Remote repeater(maybe master) always denoted with pattern at offset 0x08

####Sequence Number
 Looping 0x00-0xFF for each packet or set of packets. Does not Increment for Sync Frames. 
 
####Packet Type
Seems to Signify the type of packet, or what pattern occurs at offset 00
* 0x01 = Voice Frame
* 0x02 = Start Of Transmission or Sync Frame
* 0x03 = End of Transmission 
* 0x41 = "A" as a part of "AZZZ"
* 0x42 = "B" as a part of "BZZZ"
* 0x43 = "C" as a part of "CZZZ"

####Offset 09 ASCII
Only occurs when the value at offset 8 is "A | B | C". Always associated with pattern at Offset 0x00
          
####Slot
* "1111" = Slot 1
* "2222" = Slot 2

####Packet Type 2
The rest of the packet structure can change depending on the value of Packet Type 2.
* "DDDD" = Startup packet
* "1111" = Startup packet
* "EEEE" = Sync packet  
* "7777" = Voice packet
* "8888" = Voice packet
* "9999" = Voice packet
* "AAAA" = Voice packet
* "BBBB" = Voice packet
* "CCCC" = Voice packet
* "2222" = End of Transmission
* "FFFF" = Status Packet

####DMR Flag
All Voice, Data, Sync and Status DMR Packets have this set, and have a payload size of 72 bytes 
* "1111" - Always
 
####Payload Type
* "0000" Voice
* "DDDD" Voice (Filtered?)
* "6666" Data 
* "1111" Sync 

####Voice & Data Service Packets

####AMBE+2 Payload
Offset 26 to high order nibble of 39 and low order nibble 44 through 58.

####Destination Type
* 0x00 = Private Call 
* 0x01 = Group Call

####Destination Group ID
24 Bits Little Endian

####Source Radio ID
24 Bits Little Endian. First Bit is always 00 - Possible BUG?!

###Sync Service Packets

```
|------------------------------------------------------------------------------------------------------------------------------------------------|
|0                   1                   2                   3                   4                   5                   6                   7   |
|0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
|------------------------------------------------------------------------------------------------------------------------------------------------|
|<4 BYTE><>      <>              <sn>11111111<dt>                <DEST ID >  <SRC  ID >< unid data                              ><gid ><sid >    |
|------------------------------------------------------------------------------------------------------------------------------------------------|
```
####Destination ID
Bytes At Offset 32, 34, 36, each prepended with 0x00

####Source Radio ID
Bytes At Offset 38, 40, 42, each prepended with 0x00

###Status Service Packets
Sent every 60 Seconds During idle and active state. Unid. repeater datablock starting at offset 24. 

```
|------------------------------------------------------------------------------------------------------------------------------------------------|
|0                   1                   2                   3                   4                   5                   6                   7   |
|0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
|------------------------------------------------------------------------------------------------------------------------------------------------|
|<4 BYTE><>      <>              <sn>FFFFF111<dt><      ><       ><     ><      ><      ><      ><      ><      >                                |
|------------------------------------------------------------------------------------------------------------------------------------------------|
```


## Networking Packet ##
New device setup and keep alive messging method
```
|    Client                 Server                Peers      |Packet Type|
|------------------------------------------------------------|-----------|
|                                                            |           |
|Hello            	                                          |\  0x01    |
|Can Do PTPP     ----->                                      |/          |
|                                                            |           | 
|			                     Ack. Assign                         |\  0x02    |
|                <-----  PTPP Dev Num                        |/          |
|                                                            |           |
|                        New device                          |\  0x06    |
|                        Seen@IP:port  ----->                |/          |
|                                                            |           |
|Can Do DMR                                                  |\  0x01    |
|(from DMR PORT) ----->                                      |/          |
|                                                            |           |
|                        Ack. Assign                         |\  0x02    |
|                <-----  DMR Dev Num                         |/          |
|                                                            |           |
|                        List of all                         |\          |
|                <-----  other dmr     ----->                | - 0x06    |
|                        dev on net                          |/          |
|                                                            |           |
| ACK. List      ----->                <-----   ACK. LIST    |   0x07    |
|                                                            |           |
|Can Do RDAC                                                 |\  0x01    |
|(from RDAC PORT)----->                                      |/          |
|                                                            |           |
|                        Ack. Assign                         |\  0x02    |
|                <-----  RDAC Dev Num                        |/          |
|                                                            |           |
|                        List of all                         |\          |
|                <-----  other RDAC    ----->                | - 0x06    |
|                        dev on net                          |/          |
|                                                            |           |
| ACK. List      ----->                <-----   ACK. LIST    |   0x07    |
|                                                            |           |
|-------------------new device setup done---------------------------------
|                                                            |           |
|                         DMR,  RDAC                         |\          |
|                <-----   DEV  TABLE   ----->                | - 0x0D    |
|                        (rep 20 sec)                        |/          |
|                                                            |           |                                                            |           |
| ACK. Table     ----->                                      |\  0x0E    |
|                                      <-----   ACK. Table   |/  0x0E    |
|                                                            |           |
|                                                            |           |
|                <----- Heart Beat req ----->                |   0x0A    |
|                        (rep 7 sec)                         |   0x0A    |
| Heart Beat req ----->                <----- Heart Beat Req |   0x0A    |
| Heart Beat req --------------------------->                |   0x0A    |
|                <--------------------------- Heart Beat Req |   0x0A    |
|                                                            |           |
|                <----- Heart Beat ACK ----->                |   NULL    |
|                ---------------------------> Heart Beat ACK |   NULL    |
| Heart Beat ACK --------------------------->                |   NULL    |
|                -----> Heart Beat ACK <-----                |   NULL    |
|                   (ack on service port)                    |           |
|------------------------------------------------------------|-----------|
```
## RDAC Packet ##
