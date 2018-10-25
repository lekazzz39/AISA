<?php
/**
 * Посредник в получении данных с livetex для estimator
 */
require '../livetex.php';
$API_PASS = '1kEK2xNjqsghjJIOHOZ1064B8rQzC71ELJBi';

$method = CIn($_POST['par'],'u','');
$pass = CIn($_POST['pass'],'u','');
if ($pass!==$API_PASS) {
    send('ERR','Ошибка метода #1');
}
$methods = ['online','data'];
if (!in_array($method, $methods)) {
    send('ERR','Ошибка метода #2');
}
$LT = new Livetex();
switch ($method) {
    case 'online':
        $LT->workersOnline();
        break;
    case 'data':
        $by_date = CIn($_POST['by_date'],'i',0);
        $default = new DateTime('-1 day');
        $date = CIn($_POST['dts'],'q','date='.$default->format('Y-m-d'));
        if ($by_date>0) {
            $LT->workersDataB($date);
        } else {
            $LT->workersData($date);
        }
        break;
}


function send($code, $data)
{
    die(json_encode([$code,$data], JSON_UNESCAPED_UNICODE));
}

/**
 * Проверка ввода и защита от инъекций кода в ввод
 * @param string $var ввод
 * @param string $var_type тип переменной:
 *      's' - сильно фильтрованная строка,
 *      'k' - фильтрованная строка,
 *      'u' - минимальная фильтрация строки
 *      'i' - целое число,
 *      'r' - дробное число,
 *      'b' - логический тип данных,
 *      'd' - дата.
 * @return bool|float|int|string
 */
function CInput(&$var,$var_type)
{
    if (!isset($var)) return false;
    $var=trim((string)$var);
    if ($var_type=='k') return addslashes(strip_tags($var));
    if ($var_type=='u') return htmlspecialchars($var);
    if ($var_type=='q') return $var;
    if ($var_type=='i') return (int)$var;
    if ($var_type=='r') return (real)str_replace(',','.',$var);
    if ($var_type=='b') return (boolean)$var;
    if ($var_type=='d') return strtotime($var);
    return false;
}
/**
 * Фильтрация ввода с переменной по-умолчанию при отсутствии переменной
 * @param mixed $val Значение
 * @param string $var_type Тип переменной
 * @param string $default значение по-умолчанию
 * @return bool|float|int|string
 */
function CIn(&$val, $var_type = 's', $default = '')
{
    if ((!isset($val))||($val==='')) return CInput($default, $var_type);
    return CInput($val, $var_type);
}