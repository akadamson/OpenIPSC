hyteramon.c

Hytera Voice / Data traffic format

2012-12-06 18:38:30 172.30.10.2 30001 1 1 03144002 00000001 1 1  

COL 1	Date  
COL 2	Time in UTC  
COL 3	IP address of Repeater  
COL 4 UDP port where packet originated  
COL 5	Status of this slot. 0 = inactive, 1 = active  
COL 6	Slot Number 1 = Slot 1, 2 = Slot 2  
COL 7 Source Raidio ID number  
COL 8	Destination Group ID  
COL 9	Destination Type: 1 = Group, 2 = Private, 3 = All Call  
COL 10	Call Type: 1 = Voice, 2 = Data  


Hytera Repeater Status format


-- COMING SOON --


Trbomon.c  

MotoTRBO Voice / Data traffic Format

2012-09-16 23:11:15 50201 80 312601 145 3126002 2 02 00004e00 20 80 dd 64761 1183fed8 0  01 80 11 84 0a 96  

COL 1 	Date  
COL 2 	TIME  
COL 3   Source Network  
COL 4   Packet Type  
COL 5   Source Repeater ID  
COL 6   Call Sequence Number  
COL	7   Destination ID  
COL 8   Prio - Voice / Data  
COL 9   Flow Control Flags  
COL 10  CallControlInfo  
COL 11  ContribSrcID  
COL 12	Payload Type  
COL 13	Sequence Number  
COL 14	TimeStamp  
COL 15	SyncSrcID  
COL 16	DataTypeVoiceHeader  
COL 17	RSSI Threshold and Parity Values  
COL 18	Length in words to follow  
COL 19	Rssi Status  
COL 20	Slot Type  
COL 21	Data Size  

MotoTRBO Repeater Status Format

2012-09-16 23:17:25 50201 98 312601 6a  

COL 1		Date
COL 2		Time  
COL 3		Source Network / UDP port  
COL 4		Packet Type  
COL 5		Repeater ID  
COL 6		Slot Status  

