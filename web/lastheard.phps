<?
$state_location = "http://108.34.248.47:8080/lastheard.json";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $state_location);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$json = curl_exec($ch);
curl_close($ch);
$LastHeard = json_decode($json, true);
?>
<table width="100%" border="0" cellspacing="0">
        <tr><? foreach ($LastHeard[ColumnNames] as $ColumnName){ ?> <th> <?= $ColumnName ?> </th><? };?> </tr><?
        foreach ($LastHeard[LastHeard] as $RowNum => $Row ){
                $trClass = ( $RowNum % 2 != 0 )? "odd": "even";?>
                <tr><?  foreach ($Row as $Column){?> <td class="<?= $trClass;?>"> <?= $Column ?> </td><? };?> </tr><? };?>
</table>
