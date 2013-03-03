<?php

/*
 * Abraham Williams (abraham@abrah.am) http://abrah.am
 *
 * The first PHP Library to support OAuth for Twitter's REST API.
 * 
 * EDITED QUITE MUCH..... TAT... -jooddang
 */

/* Load OAuth lib. You can find it at http://oauth.net */
require_once('OAuth.php');

/**
 * Twitter OAuth class
 */
class TwitterOAuth {
  /* Contains the last HTTP status code returned. */
  public $http_code;
  /* Contains the last API call. */
  public $url;
  /* Set up the API root URL. */
  public $host = "https://api.twitter.com/1/";
  /* Set timeout default. */
  public $timeout = 30;
  /* Set connect timeout. */
  public $connecttimeout = 30; 
  /* Verify SSL Cert. */
  public $ssl_verifypeer = FALSE;
  /* Respons format. */
  public $format = 'json';
  /* Decode returned json data. */
  public $decode_json = TRUE;
  /* Contains the last HTTP headers returned. */
  public $http_info;
  /* Set the useragnet. */
  public $useragent = 'TwitterOAuth v0.2.0-beta2';
  /* Immediately retry the API call if the response was not successful. */
  //public $retry = TRUE;

  public $fsock_host = "ssl://api.twitter.com";



  /**
   * Set API URLS
   */
  function accessTokenURL()  { return 'https://api.twitter.com/oauth/access_token'; }
  //no more use.
  //function authenticateURL() { return 'https://api.twitter.com/oauth/authenticate'; }
  function authenticateURL() { return 'https://api.twitter.com/oauth/authorize'; }
  function authorizeURL()    { return 'https://api.twitter.com/oauth/authorize'; }
  function requestTokenURL() { return 'https://api.twitter.com/oauth/request_token'; }

  /**
   * Debug helpers
   */
  function lastStatusCode() { return $this->http_status; }
  function lastAPICall() { return $this->last_api_call; }

  /**
   * construct TwitterOAuth object
   */
  function __construct($consumer_key, $consumer_secret, $oauth_token = NULL, $oauth_token_secret = NULL) {
    $this->sha1_method = new OAuthSignatureMethod_HMAC_SHA1();
    $this->consumer = new OAuthConsumer($consumer_key, $consumer_secret);
    if (!empty($oauth_token) && !empty($oauth_token_secret)) {
      $this->token = new OAuthConsumer($oauth_token, $oauth_token_secret);
    } else {
      $this->token = NULL;
    }
  }


  /**
   * Get a request_token from Twitter
   *
   * @returns a key/value array containing oauth_token and oauth_token_secret
   */
  function getRequestToken($oauth_callback = NULL) {
    $parameters = array();
    if (!empty($oauth_callback)) {
      $parameters['oauth_callback'] = $oauth_callback;
    } 
    $request = $this->oAuthRequest($this->requestTokenURL(), 'POST', $parameters, 'GET_REQUEST_TOKEN');

	//cut http header 
	$idx = strpos($request, "oauth_token");
	$request = substr($request, $idx);

    $token = OAuthUtil::parse_parameters($request);
    $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
    return $token;
  }

  /**
   * Get the authorize URL
   *
   * @returns a string
   */
  function getAuthorizeURL($token, $sign_in_with_twitter = TRUE) {
    if (is_array($token)) {
      $token = $token['oauth_token'];
    }
    if (empty($sign_in_with_twitter)) {
      return $this->authorizeURL() . "?oauth_token={$token}";
    } else {
       return $this->authenticateURL() . "?oauth_token={$token}";
    }
  }

  /**
   * Exchange request token and secret for an access token and
   * secret, to sign API calls.
   *
   * @returns array("oauth_token" => "the-access-token",
   *                "oauth_token_secret" => "the-access-secret",
   *                "user_id" => "9436992",
   *                "screen_name" => "abraham")
   */
  function getAccessToken($oauth_verifier = FALSE) {
    $parameters = array();
    if (!empty($oauth_verifier)) {
      $parameters['oauth_verifier'] = $oauth_verifier;
    }
    $request = $this->oAuthRequest($this->accessTokenURL(), 'GET', $parameters, 'GET_ACCESS_TOKEN');

	//cut http header 
	$idx = strpos($request, "oauth_token");
	$request = substr($request, $idx);

    $token = OAuthUtil::parse_parameters($request);
    $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
    return $token;
  }

  /**
   * One time exchange of username and password for access token and secret.
   *
   * @returns array("oauth_token" => "the-access-token",
   *                "oauth_token_secret" => "the-access-secret",
   *                "user_id" => "9436992",
   *                "screen_name" => "abraham",
   *                "x_auth_expires" => "0")
  function getXAuthToken($username, $password) {
    $parameters = array();
    $parameters['x_auth_username'] = $username;
    $parameters['x_auth_password'] = $password;
    $parameters['x_auth_mode'] = 'client_auth';
    $request = $this->oAuthRequest($this->accessTokenURL(), 'POST', $parameters);
    $token = OAuthUtil::parse_parameters($request);
    $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
    return $token;
  }

  function http_parse_headers($header) {
	  $retVal = array();
	  $fields = explode("\r\n", preg_replace('/\x0D\x0A[\x09\x20]+/', ' ', $header));
	  foreach( $fields as $field ) {
		  if( preg_match('/([^:]+): (.+)/m', $field, $match) ) { 
			  $match[1] = preg_replace('/(?<=^|[\x09\x20\x2D])./e', 'strtoupper("\0")', strtolower(trim($match[1])));
			  if( isset($retVal[$match[1]]) ) {
				  $retVal[$match[1]] = array($retVal[$match[1]], $match[2]);
			  } 
			  else {
				  $retVal[$match[1]] = trim($match[2]);
			  }
		  }
	  }
	  return $retVal;
  }
   */  


  function connect_to_server($msg) {

	$fp = fsockopen($fsock_host, 443) or die ("unable to open socket2");

	$bytes = fwrite ($fp, $msg);
	if ($bytes === false) {
		$this->error = "socket error : sending data failed";
		return false;
	}
	elseif ($bytes < strlen($msg)) {
		$this->error = "socket error : couldn't send whole data";
		return false;
	}

	$response = "";
		while (!feof($fp)) {
			$buf = fread ($fp, 128);
			if ($buf === false) {
				$this->error = "socket error: can't read data";
				return false;
			}
			$response .= $buf;
		}
	fclose($fp);

	if (strpos($response, "HTTP/1.1 200") !== false || strpos($response, "HTTP/1.0 200") !== false) {
		$this->http_code = 200;
	}

	return $response;
  }


  /**
   * GET wrapper for oAuthRequest.
   */
  function get($url, $parameters = array()) {
    $response = $this->oAuthRequest($url, 'GET', $parameters);
    if ($this->format === 'json' && $this->decode_json) {
      return json_decode($response);
    }
    return $response;
  }
  

  function get_credentials($url, $parameters = array()) {
    $response = $this->oAuthRequest($url, 'GET', $parameters, 'GET_CREDENTIALS');

	//cut http header
	$idx = strpos($response, 'Server:');
	$idx = strpos($response, '{', $idx);
	$response = substr($response, $idx);

    if ($this->format === 'json' && $this->decode_json) {
      return json_decode($response);
    }
    return $response;
  }
  

  /**
   * POST wrapper for oAuthRequest.
   */
  function post($url, $parameters = array()) {
    //$response = $this->oAuthRequest($url, 'POST', $parameters);

    if (strrpos($url, 'https://') !== 0 && strrpos($url, 'http://') !== 0) {
      $url = "{$this->host}{$url}.{$this->format}";
    }
	$method = 'POST';
    $request = OAuthRequest::from_consumer_and_token($this->consumer, $this->token, $method, $url, $parameters);
    $request->sign_request($this->sha1_method, $this->consumer, $this->token);
      
	$url = $request->get_normalized_http_url(); 
	$postfields = $request->to_postdata() ;

	$tok = strtok($postfields, "&");
	while ($tok !== false) {
		$toks[] = $tok;
		$tok = strtok("&");
	}
	$auth = '';
	$postbody = '';
	foreach ($toks as $fields) {
		if (strstr($fields, "status")) {
			$postbody = $fields;
		}
		else
		{
			$auth .= strtok($fields, "=");
			$cc = strtok("=");
			$auth .= "=\"" . $cc . "\", ";
		}
	}
	$auth = substr($auth, 0, -2);

	$msg = "POST " . $url ."?". $postbody . " HTTP/1.1 \r\n";
	$msg .= "Host: api.twitter.com\r\n";
	$msg .= "Authorization: OAuth " . $auth . "\r\n";
	$msg .= "Connection: Keep-Alive \r\n\r\n";

	$response = $this->connect_to_server($msg);

	//cut http header
	$idx = strpos($response, 'Server:');
	$idx = strpos($response, '{', $idx);
	$response = substr($response, $idx);
	echo '<br/>responsesss[ '. $response.']<br/>';
	/*
	$headers = $this->http_parse_headers($response);
	foreach ($headers as $c) {
		list ($a, $b) = $c;
		echo 'header ['.$c.']<br/>';
	}
	*/

    if ($this->format === 'json' && $this->decode_json) {
      return json_decode($response);
    }
    return $response;
  }

  /**
   * DELETE wrapper for oAuthReqeust.
  function delete($url, $parameters = array()) {
    $response = $this->oAuthRequest($url, 'DELETE', $parameters);
    if ($this->format === 'json' && $this->decode_json) {
      return json_decode($response);
    }
    return $response;
  }
   */

  /**
   * Format and sign an OAuth / API request
   */
  function oAuthRequest($url, $method, $parameters, $type = NULL) {
    if (strrpos($url, 'https://') !== 0 && strrpos($url, 'http://') !== 0) {
      $url = "{$this->host}{$url}.{$this->format}";
    }
    $request = OAuthRequest::from_consumer_and_token($this->consumer, $this->token, $method, $url, $parameters);
    $request->sign_request($this->sha1_method, $this->consumer, $this->token);

    //switch ($method) {
    switch ($type) {
	case 'GET_CREDENTIALS':
      return $this->httpGet($request->to_url(), 'GET');
    case 'GET_ACCESS_TOKEN':
      return $this->httpGet($request->to_url(), 'POST');
    case 'GET_REQUEST_TOKEN':
      return $this->httpForRequestToken($request->get_normalized_http_url(), $method, $request->to_postdata());
    default:
    }
  }


  function httpGet($url, $method, $postfields = NULL) {
	//query string parsing
	/*
	$idx = strpos ($url, '?');
	$tok = strtok(substr($url, $idx+1), "&");
	while ($tok !== false) {
		$toks[] = $tok;
		$tok = strtok("&");
	}
	$auth = '';
	foreach ($toks as $fields) {
		$auth .= strtok($fields, "=");
		$cc = strtok("=");
		$auth .= "=\"" . $cc . "\", ";
	}
	$auth = substr($auth, 0, -2);
	*/

	$msg = $method. " " . $url . " HTTP/1.1 \r\n";
	$msg .= "Connection: Keep-Alive \r\n\r\n";

	$response = $this->connect_to_server($msg);

    return $response;
  }


  function httpForRequestToken ($url, $method, $postfields) {

	$tok = strtok($postfields, "&");
	while ($tok !== false) {
		$toks[] = $tok;
		$tok = strtok("&");
	}
	$auth = '';
	foreach ($toks as $fields) {
		$auth .= strtok($fields, "=");
		$cc = strtok("=");
		$auth .= "=\"" . $cc . "\", ";
	}
	$auth = substr($auth, 0, -2);
	// echo 'auth ['.$auth.']<br/><br/>';

	$msg = "POST /oauth/request_token HTTP/1.1\r\n";
	$msg .= "Host: api.twitter.com\r\n";
	$msg .= "Authorization: OAuth " . $auth . "\r\n";
	$msg .= "Connection: Keep-Alive \r\n\r\n";

	$response = $this->connect_to_server($msg);

    return $response;
  }

  /**
   * Make an HTTP request
   *
   * @return API results
   */
/*
  function http($url, $method, $postfields = NULL) {

    $this->http_info = array();
    $ci = curl_init();
    // Curl settings 
    curl_setopt($ci, CURLOPT_USERAGENT, $this->useragent);
    curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connecttimeout);
    curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout);
    curl_setopt($ci, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ci, CURLOPT_HTTPHEADER, array('Expect:'));
    curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->ssl_verifypeer);
    curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
    curl_setopt($ci, CURLOPT_HEADER, FALSE);

    switch ($method) {
      case 'POST':
        curl_setopt($ci, CURLOPT_POST, TRUE);
        if (!empty($postfields)) {
          curl_setopt($ci, CURLOPT_POSTFIELDS, $postfields);
		  echo 'postfielddd :[' . $postfields . '] count:' . strlen($postfields);
        }
        break;
      case 'DELETE':
        curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'DELETE');
        if (!empty($postfields)) {
          $url = "{$url}?{$postfields}";
        }
    }

    curl_setopt($ci, CURLOPT_URL, $url);
    $response = curl_exec($ci);
    $this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE);
    $this->http_info = array_merge($this->http_info, curl_getinfo($ci));
    $this->url = $url;

	$c = curl_getinfo($ci);
	foreach ($c as $ccc) {
		echo 'curl info [' . $ccc . ']<br/><br/>';
	}
	$c = curl_getinfo($ci, CURLOPT_HTTPHEADER);
	echo 'curl header info [' . $c . ']<br/><br/>';
    curl_close ($ci);

    return $response;
  }

  // Get the header info to store.
  function getHeader($ch, $header) {
    $i = strpos($header, ':');
    if (!empty($i)) {
      $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
      $value = trim(substr($header, $i + 2));
      $this->http_header[$key] = $value;
	  echo 'key[' . $key . '] value[' . $value .']<br/><br/>';
    }
    return strlen($header);
  }
}

  function httpForRequestToken2 ($url, $method, $postfields) {

	$tok = strtok($postfields, "&");
	while ($tok !== false) {
		$toks[] = $tok;
		$tok = strtok("&");
	}
	$auth = '';
	foreach ($toks as $fields) {
		$auth .= strtok($fields, "=");
		$auth .= "=\"" . strtok("=") . "\", ";
		
	}

	  $httpReq = new httpRequest ('https://api.twitter.com/oauth/request_token', HttpRequest::METH_POST);
	  $res = $httpReq->setHeaders (array('Host' => 'api.twitter.com', 'Authorization' => $auth));

	  if ($res === false) {
		  echo 'res failed <br/><br/>';
		  return;
	  }

	  try {
		  echo $httpReq->send()->getBody();
	  }
	  catch (HttpException $e) {
		  echo 'http exception' . $e;
	  }
  }
  */
