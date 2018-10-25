<?php

class IpTools
{
    /**
     * Check if ip address is valid
     *
     * @param string $ip IP address for validation
     * @param string $type Type of ip address. Possible value are: any, ipv4, ipv6
     * @param boolean $strict If true - fail validation on reserved and private ip ranges
     *
     * @return boolean True if ip is valid. False otherwise
     */
    public function validIp($ip, $type = 'any', $strict = true)
    {
        switch ($type) {
            case 'any':
                return $this->validIpv4($ip, $strict) || $this->validIpv6($ip, $strict);
                break;
            case 'ipv4':
                return $this->validIpv4($ip, $strict);
                break;
            case 'ipv6':
                return $this->validIpv6($ip, $strict);
                break;
        }
        return false;
    }

    /**
     * Check if given IP is valid ipv4 address and doesn't belong to private and
     * reserved ranges
     *
     * @param string $ip Ip address
     * @param boolean $strict If true - fail validation on reserved and private ip ranges
     *
     * @return boolean
     */
    public function validIpv4($ip, $strict = true)
    {
        $flags = FILTER_FLAG_IPV4;
        if ($strict) {
            $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, array('flags' => $flags)) !== false) {
            return true;
        }
        return false;
    }

    /**
     * Check if given IP is valid ipv6 address and doesn't belong to private ranges
     *
     * @param string $ip Ip address
     * @param boolean $strict If true - fail validation on reserved and private ip ranges
     *
     * @return boolean
     */
    public function validIpv6($ip, $strict = true)
    {
        $flags = FILTER_FLAG_IPV6;
        if ($strict) {
            $flags = FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, array('flags' => $flags)) !== false) {
            return true;
        }

        return false;
    }

    /**
     * Try to get real IP from client web request
     *
     * @return string
     */
    public function getClientIp()
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP']) && $this->validIp($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $ip) {
                if ($this->validIp(trim($ip))) {
                    return trim($ip);
                }
            }
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED']) && $this->validIp($_SERVER['HTTP_X_FORWARDED'])) {
            return $_SERVER['HTTP_X_FORWARDED'];
        }

        if (!empty($_SERVER['HTTP_FORWARDED_FOR']) && $this->validIp($_SERVER['HTTP_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_FORWARDED_FOR'];
        }

        if (!empty($_SERVER['HTTP_FORWARDED']) && $this->validIp($_SERVER['HTTP_FORWARDED'])) {
            return $_SERVER['HTTP_FORWARDED'];
        }

        return $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Convert CIDR to net range
     *
     * @TODO provide example
     *
     * @param string $net
     * @return string
     */
    public function cidrConv($net)
    {
        $start = strtok($net, '/');
        $n = 3 - substr_count($net, '.');

        if ($n > 0) {
            for ($i = $n; $i > 0; $i--) {
                $start .= '.0';
            }
        }

        $bits1 = str_pad(decbin(ip2long($start)), 32, '0', 'STR_PAD_LEFT');
        $net = pow(2, (32 - substr(strstr($net, '/'), 1))) - 1;
        $bits2 = str_pad(decbin($net), 32, '0', 'STR_PAD_LEFT');
        $final = '';

        for ($i = 0; $i < 32; $i++) {
            if ($bits1[$i] == $bits2[$i]) {
                $final .= $bits1[$i];
            }
            if ($bits1[$i] == 1 and $bits2[$i] == 0) {
                $final .= $bits1[$i];
            }
            if ($bits1[$i] == 0 and $bits2[$i] == 1) {
                $final .= $bits2[$i];
            }
        }

        return $start . " - " . long2ip(bindec($final));
    }
}

class Whois extends WhoisClient
{

    /** @var boolean Deep whois? */
    public $deepWhois = true;

    /** @inheritdoc */
    public $gtldRecurse = true;

    /** @var array Query array */
    public $query = array();

    /** @var string Network Solutions registry server */
    public $nsiRegistry = 'whois.nsiregistry.net';

    const QTYPE_UNKNOWN = 0;
    const QTYPE_DOMAIN  = 1;
    const QTYPE_IPV4    = 2;
    const QTYPE_IPV6    = 3;
    const QTYPE_AS      = 4;

    /**
     * Use special whois server (Populate WHOIS_SPECIAL array)
     *
     * @param string $tld Top-level domain
     * @param string $server Server address
     */
    public function useServer($tld, $server)
    {
        $this->WHOIS_SPECIAL[$tld] = $server;
    }

    /**
     *  Lookup query
     *
     * @param string $query Domain name or other entity
     * @param boolean $is_utf True if domain name encoding is utf-8 already, otherwise convert it with utf8_encode() first
     *
     */
    public function lookup($query = '', $is_utf = true)
    {
        // start clean
        $this->query = array('status' => '');

        $query = trim($query);

        //$idn = new \idna_convert();

        //if ($is_utf) {
        //    $query = $idn->encode($query);
        //} else {
        //    $query = $idn->encode(utf8_encode($query));
        //}

        // If domain to query was not set
        if (!isset($query) || $query == '') {
            // Configure to use default whois server
            $this->query['server'] = $this->nsiRegistry;
            return;
        }

        // Set domain to query in query array
        $this->query['query'] = $domain = $query = strtolower($query);

        // Find a query type
        $qType = $this->getQueryType($query);

        switch ($qType) {
            case self::QTYPE_IPV4:
                // IPv4 Prepare to do lookup via the 'ip' handler
                $ip = @gethostbyname($query);

                if (isset($this->WHOIS_SPECIAL['ip'])) {
                    $this->query['server'] = $this->WHOIS_SPECIAL['ip'];
                    $this->query['args'] = $ip;
                } else {
                    $this->query['server'] = 'whois.arin.net';
                    $this->query['args'] = "n $ip";
                    $this->query['file'] = 'whois.ip.php';
                    $this->query['handler'] = 'ip';
                }
                $this->query['host_ip'] = $ip;
                $this->query['query'] = $ip;
                $this->query['tld'] = 'ip';
                $this->query['host_name'] = @gethostbyaddr($ip);

                return $this->getData('', $this->deepWhois);
                break;

            case self::QTYPE_IPV6:
                // IPv6 AS Prepare to do lookup via the 'ip' handler
                $ip = @gethostbyname($query);

                if (isset($this->WHOIS_SPECIAL['ip'])) {
                    $this->query['server'] = $this->WHOIS_SPECIAL['ip'];
                } else {
                    $this->query['server'] = 'whois.ripe.net';
                    $this->query['file'] = 'whois.ip.ripe.php';
                    $this->query['handler'] = 'ripe';
                }
                $this->query['query'] = $ip;
                $this->query['tld'] = 'ip';
                return $this->getData('', $this->deepWhois);
                break;

            case self::QTYPE_AS:
                // AS Prepare to do lookup via the 'ip' handler
                $ip = @gethostbyname($query);
                $this->query['server'] = 'whois.arin.net';
                if (strtolower(substr($ip, 0, 2)) == 'as') {
                    $as = substr($ip, 2);
                } else {
                    $as = $ip;
                }
                $this->query['args'] = "a $as";
                $this->query['file'] = 'whois.ip.php';
                $this->query['handler'] = 'ip';
                $this->query['query'] = $ip;
                $this->query['tld'] = 'as';
                return $this->getData('', $this->deepWhois);
                break;
        }

        // Build array of all possible tld's for that domain
        $tld = '';
        $server = '';
        $dp = explode('.', $domain);
        $np = count($dp) - 1;
        $tldtests = array();

        for ($i = 0; $i < $np; $i++) {
            array_shift($dp);
            $tldtests[] = implode('.', $dp);
        }

        // Search the correct whois server
        $special_tlds = $this->WHOIS_SPECIAL;

        foreach ($tldtests as $tld) {
            // Test if we know in advance that no whois server is
            // available for this domain and that we can get the
            // data via http or whois request
            if (isset($special_tlds[$tld])) {
                $val = $special_tlds[$tld];

                if ($val == '') {
                    return $this->unknown();
                }

                $domain = substr($query, 0, -strlen($tld) - 1);
                $val = str_replace('{domain}', $domain, $val);
                $server = str_replace('{tld}', $tld, $val);
                break;
            }
        }

        if ($server == '') {
            foreach ($tldtests as $tld) {
                // Determine the top level domain, and it's whois server using
                // DNS lookups on 'whois-servers.net'.
                // Assumes a valid DNS response indicates a recognised tld (!?)
                $cname = $tld . '.whois-servers.net';

                if (gethostbyname($cname) == $cname) {
                    continue;
                }
                $server = $tld . '.whois-servers.net';
                break;
            }
        }

        if ($tld && $server) {
            // If found, set tld and whois server in query array
            $this->query['server'] = $server;
            $this->query['tld'] = $tld;
            $handler = '';
            foreach ($tldtests as $htld) {
                // special handler exists for the tld ?
                if (isset($this->DATA[$htld])) {
                    $handler = $this->DATA[$htld];
                    break;
                }

                // Regular handler exists for the tld ?
                if (file_exists('/home/staff2t/public_html/whois-src/whois.' . $htld . '.php')) {
                    $handler = $htld;
                    break;
                }
            }
            // If there is a handler set it
            if ($handler != '') {
                $this->query['file'] = "whois.$handler.php";
                $this->query['handler'] = $handler;
            }

            // Special parameters ?
            if (isset($this->WHOIS_PARAM[$server])) {
                $this->query['server'] = $this->query['server'] . '?' . str_replace('$', $domain,
                        $this->WHOIS_PARAM[$server]);
            }

            $result = $this->getData('', $this->deepWhois);
            $this->checkDns($result);
            return $result;
        }

        // If tld not known, and domain not in DNS, return error
        return $this->unknown();
    }

    /**
     * Unsupported domains
     */
    public function unknown()
    {
        unset($this->query['server']);
        $this->query['status'] = 'error';
        $result = array('rawdata' => array());
        $result['rawdata'][] = $this->query['errstr'][] = $this->query['query'] . ' domain is not supported';
        $this->checkDns($result);
        $this->fixResult($result, $this->query['query']);
        return $result;
    }

    /**
     * Get nameservers if missing
     */
    public function checkDns(&$result)
    {
        if ($this->deepWhois && empty($result['regrinfo']['domain']['nserver'])) {
            $ns = @dns_get_record($this->query['query'], DNS_NS);
            if (!is_array($ns)) {
                return;
            }
            $nserver = array();
            foreach ($ns as $row) {
                $nserver[] = $row['target'];
            }
            if (count($nserver) > 0) {
                $result['regrinfo']['domain']['nserver'] = $this->fixNameServer($nserver);
            }
        }
    }

    /**
     *  Fix and/or add name server information
     */
    public function fixResult(&$result, $domain)
    {
        // Add usual fields
        $result['regrinfo']['domain']['name'] = $domain;

        // Check if nameservers exist
        if (!isset($result['regrinfo']['registered'])) {
            if (function_exists('checkdnsrr') && checkdnsrr($domain, 'NS')) {
                $result['regrinfo']['registered'] = 'yes';
            } else {
                $result['regrinfo']['registered'] = 'unknown';
            }
        }

        // Normalize nameserver fields
        if (isset($result['regrinfo']['domain']['nserver'])) {
            if (!is_array($result['regrinfo']['domain']['nserver'])) {
                unset($result['regrinfo']['domain']['nserver']);
            } else {
                $result['regrinfo']['domain']['nserver'] = $this->fixNameServer($result['regrinfo']['domain']['nserver']);
            }
        }
    }

    /**
     * Guess query type
     *
     * @param string $query
     *
     * @return int Query type
     */
    public function getQueryType($query)
    {
        $ipTools = new IpTools;

        if ($ipTools->validIp($query, 'ipv4', false)) {
            if ($ipTools->validIp($query, 'ipv4')) {
                return self::QTYPE_IPV4;
            } else {
                return self::QTYPE_UNKNOWN;
            }
        } elseif ($ipTools->validIp($query, 'ipv6', false)) {
            if ($ipTools->validIp($query, 'ipv6')) {
                return self::QTYPE_IPV6;
            } else {
                return self::QTYPE_UNKNOWN;
            }
        } elseif (!empty($query) && strpos($query, '.') !== false) {
            return self::QTYPE_DOMAIN;
        } elseif (!empty($query) && strpos($query, '.') === false) {
            return self::QTYPE_AS;
        } else {
            return self::QTYPE_UNKNOWN;
        }
    }
}

class WhoisClient
{
    /** @var boolean Is recursion allowed? */
    public $gtldRecurse = false;

    /** @var int Default WHOIS port */
    public $port = 43;

    /** @var int Maximum number of retries on connection failure */
    public $retry = 0;

    /** @var int Time to wait between retries */
    public $sleep = 2;

    /** @var int Read buffer size (0 == char by char) */
    public $buffer = 1024;

    /** @var int Communications timeout */
    public $stimeout = 10;

    /** @var string[] List of servers and handlers (loaded from servers.whois) */
    public $DATA = array();

    /** @var string[] Non UTF-8 servers */
    public $NON_UTF8 = array();

    /** @var string[] List of Whois servers with special parameters */
    public $WHOIS_PARAM = array();

    /** @var string[] TLD's that have special whois servers or that can only be reached via HTTP */
    public $WHOIS_SPECIAL = array();

    /** @var string[] Handled gTLD whois servers */
    public $WHOIS_GTLD_HANDLER = array();

    /** @var string[] Array to contain all query publiciables */
    public $query = array(
        'tld' => '',
        'type' => 'domain',
        'query' => '',
        'status',
        'server'
    );

    /** @var string Current release of the package */
    public $codeVersion = null;

    /** @var string Full code and data version string (e.g. 'Whois2.php v3.01:16') */
    public $version;

    /**
     * Constructor function
     */
    public function __construct()
    {
        // Load DATA array
        $servers = require_once('whois.servers.php');

        $this->DATA               = $servers['DATA'];
        $this->NON_UTF8           = $servers['NON_UTF8'];
        $this->WHOIS_PARAM        = $servers['WHOIS_PARAM'];
        $this->WHOIS_SPECIAL      = $servers['WHOIS_SPECIAL'];
        $this->WHOIS_GTLD_HANDLER = $servers['WHOIS_GTLD_HANDLER'];

        $this->codeVersion = "";//file_get_contents(__DIR__ . '/../VERSION');
        // Set version
        $this->version ="";// sprintf("phpWhois v%s", $this->codeVersion);
    }

    /**
     * Perform lookup
     *
     * @return array Raw response as array separated by "\n"
     */
    public function getRawData($query)
    {

        $this->query['query'] = $query;

        // clear error description
        if (isset($this->query['errstr'])) {
            unset($this->query['errstr']);
        }

        if (!isset($this->query['server'])) {
            $this->query['status'] = 'error';
            $this->query['errstr'][] = 'No server specified';
            return (array());
        }

        // Check if protocol is http
        if (substr($this->query['server'], 0, 7) == 'http://' ||
            substr($this->query['server'], 0, 8) == 'https://'
        ) {
            $output = $this->httpQuery($this->query['server']);

            if (!$output) {
                $this->query['status'] = 'error';
                $this->query['errstr'][] = 'Connect failed to: ' . $this->query['server'];
                return (array());
            }

            $this->query['args'] = substr(strchr($this->query['server'], '?'), 1);
            $this->query['server'] = strtok($this->query['server'], '?');

            if (substr($this->query['server'], 0, 7) == 'http://') {
                $this->query['server_port'] = 80;
            } else {
                $this->query['server_port'] = 443;
            }
        } else {
            // Get args
            if (strpos($this->query['server'], '?')) {
                $parts = explode('?', $this->query['server']);
                $this->query['server'] = trim($parts[0]);
                $query_args = trim($parts[1]);

                // replace substitution parameters
                $query_args = str_replace('{query}', $query, $query_args);
                $query_args = str_replace('{version}', 'phpWhois' . $this->codeVersion, $query_args);

                $iptools = new IpTools;
                if (strpos($query_args, '{ip}') !== false) {
                    $query_args = str_replace('{ip}', $iptools->getClientIp(), $query_args);
                }

                if (strpos($query_args, '{hname}') !== false) {
                    $query_args = str_replace('{hname}', gethostbyaddr($iptools->getClientIp()), $query_args);
                }
            } else {
                if (empty($this->query['args'])) {
                    $query_args = $query;
                } else {
                    $query_args = $this->query['args'];
                }
            }

            $this->query['args'] = $query_args;

            if (substr($this->query['server'], 0, 9) == 'rwhois://') {
                $this->query['server'] = substr($this->query['server'], 9);
            }

            if (substr($this->query['server'], 0, 8) == 'whois://') {
                $this->query['server'] = substr($this->query['server'], 8);
            }

            // Get port
            if (strpos($this->query['server'], ':')) {
                $parts = explode(':', $this->query['server']);
                $this->query['server'] = trim($parts[0]);
                $this->query['server_port'] = trim($parts[1]);
            } else {
                $this->query['server_port'] = $this->port;
            }

            // Connect to whois server, or return if failed
            $ptr = $this->connect();

            if ($ptr === false) {
                $this->query['status'] = 'error';
                $this->query['errstr'][] = 'Connect failed to: ' . $this->query['server'];
                return array();
            }

            stream_set_timeout($ptr, $this->stimeout);
            stream_set_blocking($ptr, 0);

            // Send query
            fputs($ptr, trim($query_args) . "\r\n");

            // Prepare to receive result
            $raw = '';
            $start = time();
            $null = null;
            $r = array($ptr);

            while (!feof($ptr)) {
                if (!empty($r)) {
                    if (stream_select($r, $null, $null, $this->stimeout)) {
                        $raw .= fgets($ptr, $this->buffer);
                    }
                }

                if (time() - $start > $this->stimeout) {
                    $this->query['status'] = 'error';
                    $this->query['errstr'][] = 'Timeout reading from ' . $this->query['server'];
                    return array();
                }
            }

            //if (array_key_exists($this->query['server'], $this->NON_UTF8)) {
           //     $raw = utf8_encode($raw);
            //}

            $output = explode("\n", $raw);

            // Drop empty last line (if it's empty! - saleck)
            if (empty($output[count($output) - 1])) {
                unset($output[count($output) - 1]);
            }
        }

        return $output;
    }

    /**
     * Perform lookup
     *
     * @return array The *rawdata* element contains an
     * array of lines gathered from the whois query. If a top level domain
     * handler class was found for the domain, other elements will have been
     * populated too.
     */

    public function getData($query = '', $deep_whois = true)
    {

        // If domain to query passed in, use it, otherwise use domain from initialisation
        $query = !empty($query) ? $query : $this->query['query'];

        $output = $this->getRawData($query);

        // Create result and set 'rawdata'
        $result = array('rawdata' => $output);
        $result = $this->setWhoisInfo($result);

        // Return now on error
        if (empty($output)) {
            return $result;
        }

        // If we have a handler, post-process it with it
        if (isset($this->query['handler'])) {
            // Keep server list
            $servers = $result['regyinfo']['servers'];
            unset($result['regyinfo']['servers']);

            // Process data
            $result = $this->process($result, $deep_whois);

            // Add new servers to the server list
            if (isset($result['regyinfo']['servers'])) {
                $result['regyinfo']['servers'] = array_merge($servers, $result['regyinfo']['servers']);
            } else {
                $result['regyinfo']['servers'] = $servers;
            }

            // Handler may forget to set rawdata
            if (!isset($result['rawdata'])) {
                $result['rawdata'] = $output;
            }
        }

        // Type defaults to domain
        if (!isset($result['regyinfo']['type'])) {
            $result['regyinfo']['type'] = 'domain';
        }

        // Add error information if any
        if (isset($this->query['errstr'])) {
            $result['errstr'] = $this->query['errstr'];
        }

        // Fix/add nameserver information
        if (method_exists($this, 'fixResult') && $this->query['tld'] != 'ip') {
            $this->fixResult($result, $query);
        }

        return ($result);
    }

    /**
     * Adds whois server query information to result
     *
     * @param $result array Result array
     * @return array Original result array with server query information
     */
    public function setWhoisInfo($result)
    {
        $info = array(
            'server' => $this->query['server'],
        );

        if (!empty($this->query['args'])) {
            $info['args'] = $this->query['args'];
        } else {
            $info['args'] = $this->query['query'];
        }

        if (!empty($this->query['server_port'])) {
            $info['port'] = $this->query['server_port'];
        } else {
            $info['port'] = 43;
        }

        if (isset($result['regyinfo']['whois'])) {
            unset($result['regyinfo']['whois']);
        }

        if (isset($result['regyinfo']['rwhois'])) {
            unset($result['regyinfo']['rwhois']);
        }

        $result['regyinfo']['servers'][] = $info;

        return $result;
    }

    /**
     * Convert html output to plain text
     *
     * @return array Rawdata
     */
    public function httpQuery()
    {

        //echo ini_get('allow_url_fopen');
        //if (ini_get('allow_url_fopen'))
        $lines = @file($this->query['server']);

        if (!$lines) {
            return false;
        }

        $output = '';
        $pre = '';

        while (list($key, $val) = each($lines)) {
            $val = trim($val);

            $pos = strpos(strtoupper($val), '<PRE>');
            if ($pos !== false) {
                $pre = "\n";
                $output .= substr($val, 0, $pos) . "\n";
                $val = substr($val, $pos + 5);
            }
            $pos = strpos(strtoupper($val), '</PRE>');
            if ($pos !== false) {
                $pre = '';
                $output .= substr($val, 0, $pos) . "\n";
                $val = substr($val, $pos + 6);
            }
            $output .= $val . $pre;
        }

        $search = array(
            '<BR>', '<P>', '</TITLE>',
            '</H1>', '</H2>', '</H3>',
            '<br>', '<p>', '</title>',
            '</h1>', '</h2>', '</h3>');

        $output = str_replace($search, "\n", $output);
        $output = str_replace('<TD', ' <td', $output);
        $output = str_replace('<td', ' <td', $output);
        $output = str_replace('<tr', "\n<tr", $output);
        $output = str_replace('<TR', "\n<tr", $output);
        $output = str_replace('&nbsp;', ' ', $output);
        $output = strip_tags($output);
        $output = explode("\n", $output);

        $rawdata = array();
        $null = 0;

        while (list($key, $val) = each($output)) {
            $val = trim($val);
            if ($val == '') {
                if (++$null > 2) {
                    continue;
                }
            } else {
                $null = 0;
            }
            $rawdata[] = $val;
        }
        return $rawdata;
    }

    /**
     * Open a socket to the whois server.
     *
     * @param string|null $server Server address to connect. If null, $this->query['server'] will be used
     *
     * @return resource|false Returns a socket connection pointer on success, or -1 on failure
     */
    public function connect($server = null)
    {

        if (empty($server)) {
            $server = $this->query['server'];
        }

        /** @TODO Throw an exception here */
        if (empty($server)) {
            return false;
        }

        $port = $this->query['server_port'];

        $parsed = $this->parseServer($server);
        $server = $parsed['host'];

        if (array_key_exists('port', $parsed)) {
            $port = $parsed['port'];
        }

        // Enter connection attempt loop
        $retry = 0;

        while ($retry <= $this->retry) {
            // Set query status
            $this->query['status'] = 'ready';

            // Connect to whois port
            $ptr = @fsockopen($server, $port, $errno, $errstr, $this->stimeout);

            if ($ptr > 0) {
                $this->query['status'] = 'ok';
                return $ptr;
            }

            // Failed this attempt
            $this->query['status'] = 'error';
            $this->query['error'][] = $errstr;
            $retry++;

            // Sleep before retrying
            sleep($this->sleep);
        }

        // If we get this far, it hasn't worked
        return false;
    }

    /**
     * Post-process result with handler class.
     *
     * @return array On success, returns the result from the handler.
     * On failure, returns passed result unaltered.
     */

    public function process(&$result, $deep_whois = true)
    {

        $handler_name = str_replace('.', '_', $this->query['handler']);

        // If the handler has not already been included somehow, include it now
        $HANDLER_FLAG = sprintf("__%s_HANDLER__", strtoupper($handler_name));

        if (!defined($HANDLER_FLAG)) {
            include($this->query['file']);
        }

        // If the handler has still not been included, append to query errors list and return
        if (!defined($HANDLER_FLAG)) {
            $this->query['errstr'][] = "Can't find $handler_name handler: " . $this->query['file'];
            return $result;
        }

        if (!$this->gtldRecurse && $this->query['file'] == 'whois.gtld.php') {
            return $result;
        }

        // Pass result to handler
        $object = $handler_name . '_handler';

        $handler = new $object('');

        // If handler returned an error, append it to the query errors list
        if (isset($handler->query['errstr'])) {
            $this->query['errstr'][] = $handler->query['errstr'];
        }

        $handler->deepWhois = $deep_whois;

        // Process
        $res = $handler->parse($result, $this->query['query']);

        // Return the result
        return $res;
    }

    /**
     * Does more (deeper) whois
     *
     * @return array Resulting array
     */
    public function deepWhois($query, $result)
    {

        if (!isset($result['regyinfo']['whois'])) {
            return $result;
        }

        $this->query['server'] = $wserver = $result['regyinfo']['whois'];
        unset($result['regyinfo']['whois']);
        $subresult = $this->getRawData($query);

        if (!empty($subresult)) {
            $result = $this->setWhoisInfo($result);
            $result['rawdata'] = $subresult;

            if (isset($this->WHOIS_GTLD_HANDLER[$wserver])) {
                $this->query['handler'] = $this->WHOIS_GTLD_HANDLER[$wserver];
            } else {
                $parts = explode('.', $wserver);
                $hname = strtolower($parts[1]);

                if (($fp = @fopen('whois.gtld.' . $hname . '.php', 'r', 1)) and fclose($fp)) {
                    $this->query['handler'] = $hname;
                }
            }

            if (!empty($this->query['handler'])) {
                $this->query['file'] = sprintf('whois.gtld.%s.php', $this->query['handler']);
                $regrinfo = $this->process($subresult); //$result['rawdata']);
                $result['regrinfo'] = $this->mergeResults($result['regrinfo'], $regrinfo);
                //$result['rawdata'] = $subresult;
            }
        }

        return $result;
    }

    /**
     * Merge results
     *
     * @param array $a1
     * @param array $a2
     *
     * @return array
     */
    public function mergeResults($a1, $a2)
    {

        reset($a2);

        while (list($key, $val) = each($a2)) {
            if (isset($a1[$key])) {
                if (is_array($val)) {
                    if ($key != 'nserver') {
                        $a1[$key] = $this->mergeResults($a1[$key], $val);
                    }
                } else {
                    $val = trim($val);
                    if ($val != '') {
                        $a1[$key] = $val;
                    }
                }
            } else {
                $a1[$key] = $val;
            }
        }

        return $a1;
    }

    /**
     * Remove unnecessary symbols from nameserver received from whois server
     *
     * @param string[] $nserver List of received nameservers
     *
     * @return string[]
     */
    public function fixNameServer($nserver)
    {
        $dns = array();

        foreach ($nserver as $val) {
            $val = str_replace(array('[', ']', '(', ')'), '', trim($val));
            $val = str_replace("\t", ' ', $val);
            $parts = explode(' ', $val);
            $host = '';
            $ip = '';

            foreach ($parts as $p) {
                if (substr($p, -1) == '.') {
                    $p = substr($p, 0, -1);
                }

                if ((ip2long($p) == -1) or (ip2long($p) === false)) {
                    // Hostname ?
                    if ($host == '' && preg_match('/^[\w\-]+(\.[\w\-]+)+$/', $p)) {
                        $host = $p;
                    }
                } else {
                    // IP Address
                    $ip = $p;
                }
            }

            // Valid host name ?
            if ($host == '') {
                continue;
            }

            // Get ip address
            if ($ip == '') {
                $ip = gethostbyname($host);
                if ($ip == $host) {
                    $ip = '(DOES NOT EXIST)';
                }
            }

            if (substr($host, -1, 1) == '.') {
                $host = substr($host, 0, -1);
            }

            $dns[strtolower($host)] = $ip;
        }

        return $dns;
    }

    /**
     * Parse server string into array with host and port keys
     *
     * @param $server   server string in various formattes
     * @return array    Array containing 'host' key with server host and 'port' if defined in original $server string
     */
    public function parseServer($server)
    {
        $server = trim($server);

        $server = preg_replace('/\/$/', '', $server);
        $ipTools = new IpTools;
        if ($ipTools->validIpv6($server)) {
            $result = array('host' => "[$server]");
        } else {
            $parsed = parse_url($server);
            if (array_key_exists('path', $parsed) && !array_key_exists('host', $parsed)) {
                $host = preg_replace('/\//', '', $parsed['path']);

                // if host is ipv6 with port. Example: [1a80:1f45::ebb:12]:8080
                if (preg_match('/^(\[[a-f0-9:]+\]):(\d{1,5})$/i', $host, $matches)) {
                    $result = array('host' => $matches[1], 'port' => $matches[2]);
                } else {
                    $result = array('host' => $host);
                }
            } else {
                $result = $parsed;
            }
        }
        return $result;
    }
}