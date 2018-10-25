<?php

if (!isset($_GET['host'])) die('error');

$scan = dns_records_export($_GET['host'],DNS_ANY);
if ($scan===false) die('error');

die(json_encode($scan,JSON_UNESCAPED_UNICODE));


function dns_records_export($host,$ttu) {
    $records = dns_get_record($host,$ttu);
    if (count($records)<1) return false;
    $result = ['NS'=>[],'MX'=>[],'A'=>[],'AAAA'=>[],'TXT'=>[]];
    foreach ($records as $a=>$d) {
        if ($d['host']!=$host) continue;
        if ($d['type']=='NS') $result['NS'][]=$d['target'];
        if ($d['type']=='MX') $result['MX'][]=$d['target'];
        if ($d['type']=='A') $result['A'][]=$d['ip'];
        if ($d['type']=='AAAA') $result['AAAA'][]=$d['ipv6'];
        if ($d['type']=='TXT') $result['TXT'][]=$d['txt'];
    }
    return $result;
}


