<?php
/**
 * whatsmyip.help Node Script
 *
 * Author: Zac Dreyer (zac@dreycor.com)
 *
 * Requires PHP7.4+
 */


/**
 * Headers Needed
 */
header("Access-Control-Allow-Origin: https://whatsmyip.help");
header("Access-Control-Allow-Credentials: true ");
header("Access-Control-Allow-Methods: OPTIONS, GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control");


/**
 * Handle format parameter and output. Available options are json and xml
 */
$format = $_REQUEST['format'];
switch (strtolower($format)) {
    case 'xml':
        xmlOutput([
            getClientIP() => 'ip'
        ]);
        break;
    default:
        jsonOutput([
            'ip' => getClientIP()
        ]);
        break;
}


function jsonOutput($content_array){
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($content_array);
    exit();
}

function xmlOutput($content_array){
    header('Content-Type: text / xml');
    $xml = new SimpleXMLElement('<root/>');
    array_walk_recursive($content_array, array ($xml, 'addChild'));
    echo $xml->asXML();
    exit();
}


/**
 * Gets, validates and returns the connecting client's IP
 */
function getClientIP(){

    // Get real visitor IP behind CloudFlare network
    if (!empty($_SERVER["HTTP_CF_CONNECTING_IP"]) && validateIP($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER["HTTP_CF_CONNECTING_IP"];
    }

    // Get real visitor IP behind NGINX proxy - https://easyengine.io/tutorials/nginx/forwarding-visitors-real-ip/
    if (!empty($_SERVER["HTTP_X_REAL_IP"]) && validateIP($_SERVER['HTTP_X_REAL_IP'])) {
        return $_SERVER["HTTP_X_REAL_IP"];
    }

    // Check for shared Internet/ISP IP
    if (!empty($_SERVER['HTTP_CLIENT_IP']) && validateIP($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }

    // Check for IP addresses passing through proxies
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {

        // Check if multiple IP addresses exist in var
        if (strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ',') !== false) {
            $iplist = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach ($iplist as $ip) {
                if (validateIP($ip))
                    return $ip;
            }
        }
        else {
            if (validateIP($_SERVER['HTTP_X_FORWARDED_FOR']))
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED']) && validateIP($_SERVER['HTTP_X_FORWARDED']))
        return $_SERVER['HTTP_X_FORWARDED'];

    if (!empty($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']) && validateIP($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']))
        return $_SERVER['HTTP_X_CLUSTER_CLIENT_IP'];

    if (!empty($_SERVER['HTTP_FORWARDED_FOR']) && validateIP($_SERVER['HTTP_FORWARDED_FOR']))
        return $_SERVER['HTTP_FORWARDED_FOR'];

    if (!empty($_SERVER['HTTP_FORWARDED']) && validateIP($_SERVER['HTTP_FORWARDED']))
        return $_SERVER['HTTP_FORWARDED'];

    // Return unreliable IP address since all else failed
    return $_SERVER['REMOTE_ADDR'];
}

/**
 * Ensures an IP address is both a valid IP address and does not fall within
 * a private network range.
 */
function validateIP($ip) {

    if (strtolower($ip) === 'unknown')
        return false;

    // Generate IPv4 network address
    $ip = ip2long($ip);

    // Do additional filtering on IP
    if(!filter_var($ip, FILTER_VALIDATE_IP))
        return false;

    // If the IP address is set and not equivalent to 255.255.255.255
    if ($ip !== false && $ip !== -1) {

        // Make sure to get unsigned long representation of IP address
        // due to discrepancies between 32 and 64 bit OSes and
        // signed numbers (ints default to signed in PHP)
        $ip = sprintf('%u', $ip);

        // Do private network range checking
        if ($ip >= 0 && $ip <= 50331647)
            return false;
        if ($ip >= 167772160 && $ip <= 184549375)
            return false;
        if ($ip >= 2130706432 && $ip <= 2147483647)
            return false;
        if ($ip >= 2851995648 && $ip <= 2852061183)
            return false;
        if ($ip >= 2886729728 && $ip <= 2887778303)
            return false;
        if ($ip >= 3221225984 && $ip <= 3221226239)
            return false;
        if ($ip >= 3232235520 && $ip <= 3232301055)
            return false;
        if ($ip >= 4294967040)
            return false;
    }
    return true;
}


