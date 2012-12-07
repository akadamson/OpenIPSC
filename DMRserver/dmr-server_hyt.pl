#!/usr/bin/perl
#
#     DAVID KIERZKOWSKI, KD8EYF
#
use DBI;                                #load db module
my ($socket,$rdata);
my ($peeraddress,$peerport);
$err = 0;
while($Frame = <STDIN>) {
	chomp $Frame;
	print "$Frame\n";
        $SqlConn ||= DBI->connect("DBI:mysql:database=dmrdb:host=localhost", "dmrprocess", "dmrprocess") or die "Can't connect to database: $DBI::errstr\n";  #connect to db
	($Date,$Time,$RepeaterID,$SourceNet,$Status,$Slot,$SourceID,$DestinationID,$Calltype,$DestinationType) = split(/ /,$Frame);       #Get The timestamp network and type of packet for pre processing
        $DateTime = $Date . " " . $Time;                                #assemble timestamp
	if ($Status == 1) {
		$Query = "INSERT INTO `dmrdb`.`UserLog` (`StartTime`, `EndTime`, `SourceNet`, `TimeSlot`, `RepeaterID`, `DmrID`, `DestinationID` ) VALUES('$DateTime','0000-00-00 00:00:00','$SourceNet', '$Slot','$RepeaterID', '$SourceID', '$DestinationID');";
		print "$Query";
	        $Statement = $SqlConn->prepare($Query);
        	$Statement->execute();
	};
};
$dbh->close;
exit;
