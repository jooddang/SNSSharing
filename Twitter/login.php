<?php
session_start();

if (empty($_SESSION['access_token']) || empty($_SESSION['access_token']['oauth_token']) || empty($_SESSION['access_token']['oauth_token_secret'])) {
	session_destroy();

	session_start();

	require_once "twitteroauth/twitteroauth.php";
	require_once "./config.php";

	$connection = new TwitterOAuth(CONSUMER_KEY, CONSUMER_SECRET);
	$request_token = $connection->getRequestToken(OAUTH_CALLBACK);

	$_SESSION['oauth_token'] = $token = $request_token['oauth_token'];
	$_SESSION['oauth_token_secret'] = $request_token['oauth_token_secret'];

	switch ($connection->http_code) {
	case 200:
			$url = $connection->getAuthorizeURL($token);
?>
			<meta http-equiv="REFRESH" content="0; url=<?=$url?>">
<?php
			break;
	default:
			//echo '<br/></br>case default. failed. http code = [' . $connection->http_code . ']';
	}
}
else {
	//TODO: Login validity check
	echo '<script> window.close();</script>';
}
 
?>
