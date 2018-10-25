<?php
/**
 * Обновление статуса операторов в memcached
 */
require 'livetex.php';

// Инициализация соединения / объектов
$ws = [];
$LT = new Livetex();
$m = new Memcached();
$m->addServer('localhost', 11211);

for ($a=1;$a<2;$a++) {
    $ws = [];
    $D = $LT->workersOnlineD();
    $too_many = ((isset($D['message'])) && ($D['message']=='Too Many Requests'));
    if ((isset($D['results']))&&(count($D['results'])>0)) {
        foreach ($D['results'] as $elemD) {
            if ($elemD['state']!='offline') {
                $ws[] = $elemD;
            }
        }
    } else {
        echo date('Y-m-d H:i:s')." TOO_MANY_ERROR".PHP_EOL;
    }
    if (!$too_many) {
        $ws['_upd'] = date('Y-m-d H:i:s');
        $m->set('livetex_online',json_encode($ws,JSON_UNESCAPED_UNICODE));
    }
}


