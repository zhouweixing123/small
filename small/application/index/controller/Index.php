<?php
namespace app\index\controller;

use think\Config;
use wlt\wxmini\WXBizDataCrypt;
use wlt\wxmini\Prpcrypt;
use wlt\wxmini\PKCS7Encoder;

class Index
{
    public function index()
    {
        $code = input("get.code","","htmlspecialchars_decode");
        $rawData = input("get.rawData","","htmlspecialchars_decode");
        $signature  = input("get.signature ","","htmlspecialchars_decode");
        $encryptedData = input("encryptedData", '', 'htmlspecialchars_decode');
        $iv = input("iv", '', 'htmlspecialchars_decode');
        $wx = Config::get('wx');
        $parames = [
            'appid' => $wx['appid'],
            'secret' => $wx['secret'],
            "js_conde" => $code,
            "grant_type" => $wx['authorization_code']
        ];
        $res = makeRequest($wx['url'],$parames);
        if ($res["code"] !== 200 || !isset($res['result'])){
            return json(ret_message("requestTokenFailed"));
        }
        $reqData = json($res['result'],true);
        if (!isset($reqData['session_key'])){
            return json(ret_message('requestTokenFailed'));
        }
        $sessionKey = $reqData['session_key'];
        $signature2 = sha1($rawData.$sessionKey);
        if ($signature2 !== $signature) return ret_message("signNotMatch");
        $pc = new WXBizDataCrypt($wx['appid'],$sessionKey);
        $errCode = $pc -> decryptData($encryptedData,$iv,$data);
        if ($errCode !== 0){
            return json(ret_message("encryptDataNotMatch"));
        }
        $data = json_decode($data,true);
        $session3rd = randomFromDev(16);
        $data['session3rd'] = $session3rd;
        cache($session3rd,$data['openId'].$sessionKey);
        return json($data);
    }

    /**
     * 发起http请求
     * @param string $url 访问路径
     * @param array $params 参数，该数组多于1个，表示为POST
     * @param int $expire 请求超时时间
     * @param array $extend 请求伪造包头参数
     * @param string $hostIp HOST的地址
     * @return array    返回的为一个请求状态，一个内容
     */
    function makeRequest($url, $params = array(), $expire = 0, $extend = array(), $hostIp = '')
    {
        if (empty($url)) {
            return array('code' => '100');
        }

        $_curl = curl_init();
        $_header = array(
            'Accept-Language: zh-CN',
            'Connection: Keep-Alive',
            'Cache-Control: no-cache'
        );
        // 方便直接访问要设置host的地址
        if (!empty($hostIp)) {
            $urlInfo = parse_url($url);
            if (empty($urlInfo['host'])) {
                $urlInfo['host'] = substr(DOMAIN, 7, -1);
                $url = "http://{$hostIp}{$url}";
            } else {
                $url = str_replace($urlInfo['host'], $hostIp, $url);
            }
            $_header[] = "Host: {$urlInfo['host']}";
        }

        // 只要第二个参数传了值之后，就是POST的
        if (!empty($params)) {
            curl_setopt($_curl, CURLOPT_POSTFIELDS, http_build_query($params));
            curl_setopt($_curl, CURLOPT_POST, true);
        }

        if (substr($url, 0, 8) == 'https://') {
            curl_setopt($_curl, CURLOPT_SSL_VERIFYPEER, FALSE);
            curl_setopt($_curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        }
        curl_setopt($_curl, CURLOPT_URL, $url);
        curl_setopt($_curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($_curl, CURLOPT_USERAGENT, 'API PHP CURL');
        curl_setopt($_curl, CURLOPT_HTTPHEADER, $_header);

        if ($expire > 0) {
            curl_setopt($_curl, CURLOPT_TIMEOUT, $expire); // 处理超时时间
            curl_setopt($_curl, CURLOPT_CONNECTTIMEOUT, $expire); // 建立连接超时时间
        }

        // 额外的配置
        if (!empty($extend)) {
            curl_setopt_array($_curl, $extend);
        }

        $result['result'] = curl_exec($_curl);
        $result['code'] = curl_getinfo($_curl, CURLINFO_HTTP_CODE);
        $result['info'] = curl_getinfo($_curl);
        if ($result['result'] === false) {
            $result['result'] = curl_error($_curl);
            $result['code'] = -curl_errno($_curl);
        }

        curl_close($_curl);
        return $result;
    }
}
