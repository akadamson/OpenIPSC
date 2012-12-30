<?php 
//lastheard.php - render webpage of dmr lasthead list
//
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
	 	<img src="hyteralogo.png" border="0" height="75" alt="logo"/>
        </div>
        <div class="nav">
            <ul>
                <li>
                    <a href="netstatus.php">NetStatus</a>
                </li>
                <li>
                    <a href="lastheard.php" class="active">LastHeard</a>
                </li>
                <li>
                    <a href="calllog.php">Call Log</a>
                </li>
                <li>
                    <a href="users.php">Users</a>
                </li>
            </ul>
        </div>
    </div>
    <div id="content" class="fixed"> 
        <div id="maincontent">
            <h2>Last Heard List</h2><?            
$state_location = "http://127.0.0.1/lastheard.json";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $state_location);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$json = curl_exec($ch);
curl_close($ch);
$LastHeard = json_decode($json, true);?>
<table width="100%" border="0" cellspacing="0">
        <tr><? foreach ($LastHeard[ColumnNames] as $ColumnName){ ?> <th> <?= $ColumnName ?> </th><? };?> </tr><?
        foreach ($LastHeard[LastHeard] as $RowNum => $Row ){
                $trClass = ( $RowNum % 2 != 0 )? "odd": "even";?>
                <tr><?  foreach ($Row as $Column){?> <td class="<?= $trClass;?>"> <?= $Column ?> </td><? };?> </tr><? };?>
</table>
