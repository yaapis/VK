<?php

/**
 * The PHP class for vk.com API and to support OAuth.
 * @author Vlad Pronsky <vladkens@yandex.ru>
 * @license http://www.gnu.org/licenses/gpl.html GPL v3
 */
class VK
{
    /**
     * VK application ID.
     * @var int
     */
    private $appId;

    /**
     * VK application secret key.
     * @var string
     */
    private $apiSecret;

    /**
     * VK access token.
     * @var string
     */
    private $accessToken;

    /**
     * Set timeout.
     * @var int
     */
    private $timeout = 30;

    /**
     * Set connect timeout.
     * @var int
     */
    private $connectTimeout = 30;

    /**
     * Check SLL certificate.
     * @var bool
     */
    private $ssl_verifypeer = false;

    /**
     * Set library version
     * @var string.
     */
    private $lib_version = '0.1';

    /**
     * Contains the last HTTP status code returned.
     * @var int
     */
    private $http_code;

    /**
     * Contains the last HTTP headers returned.
     * @var ??
     */
    private $http_info;

    /**
     * Authorization status.
     * @var bool
     */
    private $auth = false;

    /**
     * Set base API URLs.
     */
    public function baseAuthorizeURL()
    {
        return 'http://oauth.vk.com/authorize';
    }

    public function baseAccessTokenURL()
    {
        return 'https://oauth.vk.com/access_token';
    }

    public function getAPI_URL($method = '')
    {
        return 'https://api.vk.com/method/' . $method;
    }

    /**
     * @param string $app_id
     * @param string $api_secret
     * @param string $access_token
     */
    public function __construct($app_id, $api_secret, $access_token = null)
    {
        $this->appId = $app_id;
        $this->apiSecret = $api_secret;
        $this->accessToken = $access_token;

        if (!is_null($this->accessToken) && !$this->checkAccessToken()) {
            throw new VKException('Invalid access token.');
        } else {
            $this->auth = true;
        }
    }

    /* public: */

    /**
     * Returns authorization status.
     * @return bool true is auth, false is not auth
     */
    public function is_auth()
    {
        return $this->auth;
    }

    /**
     * VK API method.
     * @param string $method Contains VK API method.
     * @param array $parameters Contains settings call.
     * @return array
     */
    public function api($method, $parameters = null)
    {
        if (is_null($parameters)) $parameters = array();
        $parameters['api_id'] = $this->appId;
        $parameters['v'] = $this->lib_version;
        $parameters['method'] = $method;
        $parameters['timestamp'] = time();
        $parameters['format'] = 'json';
        $parameters['random'] = rand(0, 10000);

        if (!is_null($this->accessToken))
            $parameters['access_token'] = $this->accessToken;

        ksort($parameters);

        $sig = '';
        foreach ($parameters as $key => $value) {
            $sig .= $key . '=' . $value;
        }
        $sig .= $this->apiSecret;

        $parameters['sig'] = md5($sig);
        $query = $this->createURL($parameters, $this->getAPI_URL($method));

        return json_decode(file_get_contents($query), true);
    }

    /**
     * Get authorize URL.
     * @param string $api_settings Access rights requested by your app (through comma).
     * @param string $callback_url
     * @return string
     */
    public function getAuthorizeURL($api_settings = '', $callback_url = 'http://oauth.vk.com/blank.html')
    {

        $parameters = array(
            'client_id' => $this->appId,
            'scope' => $api_settings,
            'redirect_uri' => $callback_url,
            'response_type' => 'code'
        );

        return $this->createURL($parameters, $this->baseAuthorizeURL());
    }

    /**
     * Get the access token.
     * @param string $code The code to get access token.
     * @return array(
     *      'access_token'  => 'the-access-token',
     *      'expires_in'    => '86399', // time life token in seconds
     *      'user_id'       => '12345')
     */
    public function getAccessToken($code, $callback_url = 'http://oauth.vk.com/blank.html')
    {
//        if (!is_null($this->accessToken) && $this->auth) {
//            throw new VKException('Already authorized.');
//        }

        $parameters = array(
            'client_id' => $this->appId,
            'client_secret' => $this->apiSecret,
            'code' => $code,
            'redirect_uri' => $callback_url
        );

        $url = $this->createURL($parameters, $this->baseAccessTokenURL());
        $rs = $this->http($url);

        if (isset($rs['error'])) {
            $message = 'HTTP status code: ' . $this->http_code . '. ' . $rs['error'] . ': ' . $rs['error_description'];
            throw new VKException($message);
        } else {
            $this->auth = true;
            $this->accessToken = $rs['access_token'];
            return $rs;
        }
    }

    /* private: */

    /**
     * Make HTTP request.
     * @param string $url
     * @param string @method Get or Post
     * @param array $postfields If $method post
     * @return array API return
     */
    private function http($url, $method = 'GET', $postfields = null)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_USERAGENT, 'VK v' . $this->lib_version);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->ssl_verifypeer);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);

            if (!is_null($postfields)) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postfields);
            }
        }

        curl_setopt($ch, CURLOPT_URL, $url);

        $rs = curl_exec($ch);
        $this->http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->http_info = curl_getinfo($ch);
        curl_close($ch);

        return json_decode($rs, true);
    }

    /**
     * Create URL from the sended parameters.
     * @param array $parameters Add to base url
     * @param string $url Base url
     * @return string
     */
    private function createURL($parameters, $url)
    {
        $piece = array();
        foreach ($parameters as $key => $value)
            $piece[] = $key . '=' . rawurlencode($value);

        $url .= '?' . implode('&', $piece);
        return $url;
    }

    /**
     * Check freshness of access token.
     * @return bool true is valid access token else false
     */
    private function checkAccessToken()
    {
        if (is_null($this->accessToken)) return false;

        $response = $this->api('getUserSettings');

        return isset($response['response']);
    }

}
