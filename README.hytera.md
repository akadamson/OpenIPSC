#Hytera "Multi Site Connect" Protocol  

##VOICE / DATA PACKETS  
- UDP PAYLOAD SIZE: 72  

```
|------------------------------------------------------------------------|
|                     Hytera Voice UDP Payload                           |
|0                   1                   2                   3           | 
|0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 |
|------------------------------------------------------------------------|
|<4 BYTE><>      <><ASCI>                            <---- AMBE+2 VOICE  |
|------------------------------------------------------------------------|
```
cont...
```
|------------------------------------------------------------------------|
|3       4                   5                   6                   7   |  
|6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
|------------------------------------------------------------------------|
|----> <--SYNC --> <---- AMBE+2 VOICE    ---->       <>  <gid ><sid >    |
|------------------------------------------------------------------------|
```
### OFFSET 0 - 3
  "ZZZZ"        = some form of special frame, seems to denote that the
                  packet is from a remote repeater(maybe master)
                  always denoted with pattern at offset 0x08
  0xXXXX        = Offset 18 - 19 "BBBB" or "1111"
                  the first 2 bytes are the port number e.g. 0x7531 = 30001

OFFSET 4 
  00 to FF = Voice Frame Sequence Number Looping
             Does not Increment for Sync Frames

OFFSET 8
  0x01 = Voice Frame
  0x02 = Start Of Transmission or Sync Frame
  0x03 = End of Transmission 
  0x41 = "A" as a part of "AZZZ"
  0x42 = "B" as a part of "BZZZ"
  0x43 = "C" as a part of "CZZZ"

OFFSET 9
  "ZZZ" - only when the value at offset 8 is "A | B | C"
          always associated with pattern at Offset 0x00 noted above

OFFSET 16 - 17
  "1111" = Slot 1
  "2222" = Slot 2

OFFSET 18 - 19
  "DDDD" = Startup packet
  "1111" = Startup packet
  "EEEE" = Sync packet  
  "7777" = Voice packet
  "8888" = Voice packet
  "9999" = Voice packet
  "AAAA" = Voice packet
  "BBBB" = Voice packet
  "CCCC" = Voice packet
  "2222" = End of Transmission
  "FFFF" = Status Packet
  
  Start of Transmission SEQUENCE: DDE1E1E1
  Voice Sequence w/ Sync: 789AEBC  
  Voice Packets: 789ABC 
  
OFFSET 20 - 21
  "1111" - Always

OFFSET 22 - 23 
  PACKET TYPE
  "0000" - DMR Voice Packet?
  "DDDD" - DMR Voice Packet / Filtered?
  "6666" - Data Packet
  "1111" - Sync Packet

OFFSET 32, 34, 36 (SYNC Packets Only)
  Destination ID Bytes ( Big Endian )

OFFSET 38, 40, 42 ( Sync Packets Only )
  Source ID Bytes ( Big Endian )

OFFSET 26 - 38 plus high order nibble of 39 for 13.5 bytes
  AMBE+2 1 of 2 VOICE AND DATA 

OFFSET 39 low order nibble - 44 plus high order nibble of 45 for total of 6 bytes
  DMR Sync frame between all VOICE / DATA Packets
  
OFFSET 45 - 58 (starts at low order nibble of 45 through 58 for 13.5 bytes
  AMBE+2 2 of 2 VOICE AND DATA
  
OFFSET 62
  0x00 = Private Call
  0x01 = Group Call

OFFSET 64 - 66
  Destination Group ID ( big endian )

OFFSET 67 - 69 
  Source ID ( little endian ) - First Byte Missing
-----------------------------------------------------------------------------------------

Peer to Peer Messages  
Used to communicat device status across the network 



|--------------------------------------------------------------------|  
|                        PEER 2 PEER MESSAGE TYPE D+E                |  
|0                   1                   2                   3       |  
|0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 |  
|--------------------------------------------------------------------|  
|<ASCII  ><><           ><>              <>  <>      <  ><  ><      >|    
|                                                    <   REPEATING  >|
|---------------------------------------------------------------------  

OFFSET 00-03  
  ASCII : "PTPP" - Peer to Peer Message  
  

OFFSET 04 - MESSAGE TYPE  
  
  0x0D - MASTER -> SLAVE  
  0x0E - MASTER <- SLAVE  

OFFSET 05 - 11 
  ALWAYS "00000014000000"

OFFSET 12 - 14
  UNKNOWN

OFFSET 12  
  COUNTDOWN TIMER SEC TILL 1/4 HR  

-Master -> Slave Message

OFFSET 20  
   NUMBER OF DEVEICES IN THIS MESSAGE  

OFFSET 22  
   0x10 = NEW / LEARNING  
   0x11 = VOICE / DATA  
   0x12 = RDAC  

OFFSET 26 - 33  
  (PTPP M->S) REPEATING FOR EACH DEVICE IN MESSAGE

OFFSET 26
  xx - Device Number in Network ( 01, 02, 03 ... )
  
OFFSET 27 
  01 - REPEATER
  02 - RDAC 

OFFSET 29 - 28...  
    UPD PORT OF SLAVE REPEATER  

OFFSET 30 - 33...  
    IP ADDRESS OF SLAVE REPEATER  

-Slave -> Master Reply 
