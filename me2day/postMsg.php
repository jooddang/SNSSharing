<?php
session_start();

require_once ('./config.php');
?>

<html>
<head>
	<meta http-equiv="Content-Type" content="text/html"; charset=UTF-8" />
<?php

		if (empty($_SESSION['me2_user_id']) || empty($_SESSION['me2_user_key']) || empty($_POST['msg'])) {
			header('Location: ./clearsessions.php');
		}

	//난수 발생기
		function nonce() {
			$nonce = '';
			for ($i = 0; $i < 8; ++$i) {
				$nonce .= dechex(rand(0,15));
			}
			return $nonce;
		}

		$fp = fsockopen('me2day.net', 80, $errno, $errstr);
		if (!$fp) {
			$this->error = "socket error {$errno}:{$errstr}";
			return;
		}

		$uid = $_SESSION['me2_user_id'];
		$ukey = $_SESSION['me2_user_key'];
		if (!$ukey) {
			echo 'ukey is null';
			header('Location: ./clearsessions.php');
		}

		$data = "uid=" . $uid . "&ukey=" . $ukey . "&post[body]=" . $_POST['msg'] . "&post[tags]=" . $_POST['tag'] . "&akey=" . APP_KEY;
		$nonce = nonce();

		$msg = "POST /api/create_post/" . $uid . ".xml" . " HTTP/1.1\r\n";
		$msg .= "Host: me2day.net \r\n";
		$msg .= "Authorization: Basic " . base64_encode("{$uid}:$nonce" . md5($nonce . $ukey)) . "\r\n";
		$msg .= "Content-type: application/x-www-form-urlencoded \r\n";
		$msg .= "Content-length: ". strlen ($data) . "\r\n";
		$msg .= "Connection: close \r\n\r\n";
		$msg .= $data;
		//echo 'msg = [' . $msg . ']<br/><br/>';

		$bytes = fwrite($fp, $msg);
		if ($bytes === false) {
			//echo "socket error : sending data failed";
			return false;
		}
		elseif ($bytes < strlen($msg)) {
			//echo "socket error : couldn't send whole data";
			return false;
		}
		$response = '';
		while (!feof($fp)) {
			$buf = fread ($fp, 1024);
			if ($buf === false) {
				//echo "socket error: can't read data";
				return false;
			}
			$response .= $buf;
		}

		//echo $response;
?>
	<script> self.close();</script>
</head>

</html>
