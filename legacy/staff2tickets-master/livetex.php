<?php

/**
 * Class Livetex
 * Работа с API Livetex
 */
Class Livetex
{
    private $AUTH = ['v.tychina@timeweb.ru','s4rzf120VLy'];
    private $API = 'https://apiv2.livetex.ru/v2/';
    public function call_method($address) {
        return $this->loadPage($address, '','', $this->AUTH);
    }
    // Получения списка сотрудников онлайн
    /**
     * Получение данных по онлайну сотрудников
     * @return array|bool
     */
    public function workersOnline()
    {
        $url = $this->API.'employees/list?';
        $url.= 'fields=email,state&limit=100';
        $data = json_decode($this->call_method($url), JSON_OBJECT_AS_ARRAY);
        $this->send('OK', $data);
    }
    /**
     * Получение данных по онлайну сотрудников
     * @return array
     */
    public function workersOnlineD()
    {
        $url = $this->API.'employees/list?';
        $url.= 'fields=email,state&limit=100';
        $data = json_decode($this->call_method($url), JSON_OBJECT_AS_ARRAY);
        return $data;
    }
    /**
     * Получение данных по сотрудникам для сохранения
     */
    public function workersData($date)
    {
        $url = $this->API.'stats/employees?';
        $url.= 'q='.$date.'&limit=100&sort=chats_total:d&fields=email,chats_total,chats_first_answer_avg, visitor_votes_pos,visitor_votes_neg';
        $data = json_decode($this->call_method($url), JSON_OBJECT_AS_ARRAY);
        $this->send('OK', $data);
    }
    /**
     * Получение данных по сотрудникам для сохранения by_date
     */
    public function workersDataB($date)
    {
        $url = $this->API.'stats/employees?';
        $url.= 'q='.$date.'&limit=100&sort=chats_total:d&fields=email,chats_total,chats_first_answer_avg, visitor_votes_pos,visitor_votes_neg,by_date';
        $data = json_decode($this->call_method($url), JSON_OBJECT_AS_ARRAY);
        $this->send('OK', $data);
    }
    /**
     * Базовая функция обращения к API
     * @param string $url Адрес запроса
     * @param mixed $post POST-данные массивом при POST либо ''
     * @param mixed $headers Заголовки массивом либо ''
     * @param mixed $base_auth Данные для авторизации либо ''
     * @return mixed
     */
    private function loadPage($url, $post='', $headers='', $base_auth='') {
        $conn = curl_init();
        curl_setopt($conn, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($conn, CURLOPT_SSL_VERIFYHOST, false);
        if ((is_array($headers))&&(count($headers)>0)) curl_setopt($conn, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($conn, CURLOPT_USERAGENT,'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2');
        curl_setopt($conn, CURLOPT_URL, $url);
        curl_setopt($conn, CURLOPT_HEADER, false);
        curl_setopt($conn, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($conn, CURLOPT_FOLLOWLOCATION, true);   // переходит по редиректам
        curl_setopt($conn, CURLOPT_MAXREDIRS, 10);
        curl_setopt($conn, CURLOPT_CONNECTTIMEOUT, 15); // таймаут соединения
        curl_setopt($conn, CURLOPT_TIMEOUT, 15);        // таймаут ответа
        curl_setopt($conn, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($conn, CURLINFO_HEADER_OUT, true);
        if ((is_array($base_auth))&&(count($base_auth)==2)) {
            curl_setopt($conn, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($conn, CURLOPT_USERPWD, "{$base_auth[0]}:{$base_auth[1]}");
        }
        if ((is_array($post))&&(count($post)>0)) {
            curl_setopt($conn, CURLOPT_POST, true);
            curl_setopt($conn, CURLOPT_POSTFIELDS, http_build_query($post));
        }
        $content = curl_exec($conn);
        //$sent_headers = curl_getinfo($conn, CURLINFO_HEADER_OUT);
        if ($content===false) {
            //var_dump($url);        var_dump($sent_headers);
            //$errmsg  = curl_error( $conn );
            //if (strlen($errmsg)>1) var_dump($errmsg);
        }
        curl_close( $conn );
        return $content;
    }

    /**
     * Отправка результатов запроса клиенту
     * @param string $code Код ответа : OK, ERR
     * @param string $data Данные в формате JSON либо текст ошибки
     */
    private function send($code, $data)
    {
        die(json_encode(['info'=>$code, 'msg'=>$data],JSON_UNESCAPED_UNICODE));
    }

    /**
     * Проверка на Too Many Requests
     * @param $data array
     */
    private function is_timeout(&$data)
    {
        return ($data['message']=='Too Many Requests');
    }
}
