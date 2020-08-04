<?php
session_start();

require_once __DIR__ . '/vendor/autoload.php';

define('CLIENT_ID', '39eebdc2-ed77-4be9-99d8-6a64f4ef025a');
define('TENANT_ID', '9c9d181f-4cb2-42bd-98b3-5c09b3adde5b');
define('CLIENT_SECRET', 'BY5-Y~M5WuDNwfu-h62gsg.jMVRh017Omf');
define('EXPECTED_ALG', 'RS256');

define('BASE_URL', 'https://login.microsoftonline.com/');
define('AUTH_PATH', '/oauth2/v2.0/authorize');
define('TOKEN_PATH', '/oauth2/v2.0/token');
define('INFO_PATH', '/common/v2.0/.well-known/openid-configuration');

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

$keys = null;
try {
    $httpClient = new GuzzleHttp\Client(['base_uri' => BASE_URL]);

    $keys = new SimpleJWT\Keys\KeySet();

    $infoResponse = $httpClient->get(INFO_PATH, [
        'query' => [
            'appid' => CLIENT_ID
        ]
    ]);

    $jsonData = json_decode($infoResponse->getBody()->getContents(), true);

    if (json_last_error() != JSON_ERROR_NONE) {
        return false;
    }

    if (!isset($jsonData['jwks_uri'])) {
        return false;
    }

    $jwksPath = parse_url($jsonData['jwks_uri'], PHP_URL_PATH);

    $keysResponse = $httpClient->get($jwksPath, [
        'query' => [
            'appid' => CLIENT_ID
        ]
    ]);

    $jsonData = json_decode($keysResponse->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);

    if (!isset($jsonData['keys']) || !is_array($jsonData['keys'])) {
        throw new Exception('Bed Response');
    }

    foreach ($jsonData['keys'] as $key) {
        $keys->add(new SimpleJWT\Keys\RSAKey($key, 'php'));
    }
} catch (Exception $e) {
    echo $e->getMessage();
    die;
}

echo '<a href="/">Reset</a><br/>';

//Create redirect.


$state = base64url_encode(random_bytes(32));
$redirectUri = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https://" : "http://" . $_SERVER['HTTP_HOST'] . '/redirect';

$loginRedirectUrl = BASE_URL . TENANT_ID . AUTH_PATH . '?' .
    'client_id=' . CLIENT_ID . '&' .
    'response_type=code&' .
    'redirect_uri=' . urlencode($redirectUri) . '&' .
    'scope=openid&' .
    'state=' . $state;



if (isset($_SERVER['PATH_INFO'])) {
    $path = $_SERVER['PATH_INFO'];
} else {
    $path = '/';
}

switch ($path) {
    case '/redirect':

        if (!isset($_SESSION['state']) || !isset($_GET['state']) || $_GET['state'] != $_SESSION['state']) {
            var_dump($_SESSION['state']);
            var_dump($_GET['state']);
            die('State Mismatch');
        }

        if (!isset($_GET['code'])) {
            die('Missing Code');
        }

        $code = $_GET['code'];

        try {
            $response = $httpClient->request('POST', TENANT_ID . TOKEN_PATH, [
                'form_params' => [
                    'client_id' => CLIENT_ID,
                    'scope' => 'openid',
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'redirect_uri' => $redirectUri,
                    'client_secret' => CLIENT_SECRET
                ]
            ]);

            $jsonString = $response->getBody()->getContents();
            $jsonData = json_decode($jsonString, true);

            if (json_last_error() != JSON_ERROR_NONE) {
                die('JSON Decode failed "' . json_last_error_msg().'"');
            }

            if (!isset($jsonData['id_token'])) {
                die('Missing Id Token');
            }

            if (!isset($jsonData['access_token'])) {
                die('Missing Access Token');
            }

            if ($keys === null) {
                die('Failed loading public keys');
            }

            if (isset($jsonData['id_token'])) {
                echo '<h1>ID Token</h1>';

                $idToken = SimpleJWT\JWT::decode($jsonData['id_token'], $keys, EXPECTED_ALG);

                echo $jsonData['id_token'];

                echo '<pre>';
                var_dump($idToken->getClaims());
                echo '</pre>';
            }

        } catch (Exception $exception) {
            echo get_class($exception) . '<br/>';
            echo $exception->getMessage() . '<br/>';
            die;
        }
        break;
    default:
        $_SESSION['state'] = $state;
        header('Location: ' . $loginRedirectUrl);
        break;
}