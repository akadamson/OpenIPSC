<?php 
//users.php - render webpage of dmr users
//Copyright (C) 2012 David Kierzokwski (kd8eyf@digitalham.info)
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 ?>
<html>
    <body>
    <link rel="stylesheet" href="netstatus.css" type="text/css">
    <div id="header" class="fixed">
        <div class="logo">                
            <img src="logo.png" border="0" width="300" height="75" alt="logo" /></div>
		</a>
        <div class="nav">
            <ul>
                <li>
                    <a href="netstatus.php">NetStatus</a>
                </li>
                <li>
                    <a href="lastheard.php">LastHeard</a>
                </li>
                <li>
                    <a href="calllog.php">Call Log</a>
                </li>
                <li>
                    <a href="users.php" class="active">Users</a>
                </li>
            </ul>
        </div>
    </div>
    <div id="content" class="fixed"> 
        <div id="maincontent">
            <h2>Welcome Newest Michigan DMR subscribers</h2>
            
            <table  width="100%" border="0" cellspacing="0" >
                <tr>
                    <th>Radio ID</th>
                    <th>User Name</th>
                    <th>Callsign</th>
                    <th>City</th>
                    <th>Radio</th>
                
                <tr>
                <? 
include '/usr/local/include/dmrdb.inc' ;
date_default_timezone_set( 'UTC' ) ;
$Date = date( 'l F jS, Y', time() ) ;
$DateTime = date( 'd M y, H:i:s', time() ) ;

    
$Query = "SELECT ChangeLog.DateTime, ChangeLog.DmrID, User.name, User.Callsign, User.City, User.Radio FROM `ChangeLog` LEFT JOIN `User` ON `ChangeLog`.`DmrID` = `User`.`DmrID`WHERE `ChangeLog`.`DmrID` LIKE '3126___' AND `RecordType` LIKE 'User' AND `FieldName` LIKE 'DmrID' GROUP BY `CallSign` ORDER BY DateTime DESC , DmrID DESC";

mysql_query( $Query ) or die( "MYSQL ERROR:" . mysql_error() ) ;
$Result = mysql_query( $Query ) or die( mysql_errno . " " . mysql_error() ) ;
while ( $User = mysql_fetch_array( $Result ) ) { ?>
                <tr>
                    
                    <td nowrap class=<?=$RowClass?>><?=$User[1]?></td>
                    <td nowrap class=<?=$RowClass?>><?=$User[2]?></td>
                    <td nowrap class=<?=$RowClass?>><?=$User[3]?></td>
                    <td nowrap class=<?=$RowClass?>><?=$User[4]?></td>
                    <td nowrap class=<?=$RowClass?>><?=$User[5]?></td></td>
                </tr>
                <?
    $i++ ;
} ?>
            </table>
            <br />
        </div>
    </div>
    <div id="footer" class="fixed">
        <a href="https://github.com/KD8EYF/OpenIPSC">OpenIPSC DMR Monitor</a>
        <div id="credits">&copy 2012 KD8EYF</div>
    </div>    
    </body>
</html>
<? 
function duration( $seconds ){
	$days = floor( $seconds / 60 / 60 / 24 ) ;
	$hours = $seconds / 60 / 60 % 24 ;
	$mins = $seconds / 60 % 60 ;
	$secs = $seconds % 60 ;
	$duration = '' ;
	if ( $days > 0 ) {
		$duration = "$days" . "D " ;
	} elseif ( $hours > 0 ) $duration .= "$hours" . "H " ;
	if ( $mins > 0 ) $duration .= "$mins" . "M " ;
	if ( ( $secs > 0 ) && ( $hours < 1 ) && ( $mins < 10 ) ) $duration .= "$secs" . "S " ;
	$duration = trim( $duration ) ;
	if ( $seconds >= 365 * 24 * 60 ) { $duration = "NEVER" ; }	;
	if ( $duration == null ) $duration = '0' . 'S' ;
	if ( $seconds >= 1000000000 ) $duration = "NEVER" ;
	return $duration ;}
?>