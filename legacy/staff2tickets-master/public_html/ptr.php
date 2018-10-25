<?php

if (!isset($_GET['host'])) die('error');

$scan = gethostbyaddr($_GET['host']);
if ($scan===false) die('error');

die($scan);
