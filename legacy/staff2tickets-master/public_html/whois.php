<?php
require "whois-src/ewhois.php";
if (!isset($_GET['host'])) die('error');

$host = $_GET['host'];
$whois = new Whois();
$result = $whois->lookup($host);
$reg_status = $result['regrinfo']['registered'];
$whois_ns='';$whois_exp='';$whois_reg='';$whois_status='';$dns=[];
if ($reg_status=='yes') {
    if (isset($result['regrinfo']['domain']['nserver'])) $whois_ns = implode(', ',array_keys($result['regrinfo']['domain']['nserver']));
    if (isset($result['regrinfo']['domain']['expires'])) $whois_exp = $result['regrinfo']['domain']['expires'];
    if (isset($result['regrinfo']['domain']['sponsor'])) $whois_reg = $result['regrinfo']['domain']['sponsor'];
    if (isset($result['regrinfo']['domain']['status'])) $whois_status = $result['regrinfo']['domain']['status'];
}
$result = ['registred'=>$reg_status,'ns'=>$whois_ns,'exp'=>$whois_exp,'reg'=>$whois_reg,'status'=>$whois_status];

die(json_encode($result,JSON_UNESCAPED_UNICODE));


