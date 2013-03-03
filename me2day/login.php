<html>
<head>
<?php

		require_once('./config.php');

		$fp = fsockopen ('me2day.net', 80, $errno, $errstr, 10);
		if (!$fp) {
			$this->error = "socket error {$errno}:{$errstr}";
			echo 'fp is null [' . $this->error . ']';
			return;
		}

		$msg = "GET /api/get_auth_url.json?akey=". APP_KEY . " HTTP/1.1\r\nHost: me2day.net " . "\r\nConnection: Close \r\n\r\n";

		$bytes = fwrite($fp, $msg);
		if ($bytes === false) {
			$this->error = "socket error : sending data failed";
			//echo 'error 2 [' . $this->error . ']';
			return false;
		}
		elseif ($bytes < strlen($msg)) {
			$this->error = "socket error : couldn't send whole data";
			//echo 'error 3 [' . $this->error . ']';
			return false;
		}

		$response = '';
		while (!feof($fp)) {
			$buf = fread ($fp, 128);
			if ($buf === false) {
				$this->error = "socket error: can't read data";
				//echo 'error 4 [' . $this->error . ']';
				return false;
			}
			$response .= $buf;
		}
		if ($response === '') {
			//echo 'nuuuuulll';
		}
		$response = strstr($response, "{\"token");
		$data = json_decode($response);
		//echo '<br/><br/>reponse =[' . $response . ']';
		//echo '<br/><br/>URL =[' . $data->{'url'} . ']';
		$url = $data->{'url'};

		//header ("Location: {$response['url']}");
		fclose($fp);

?>
		<meta http-equiv="REFRESH" content="2;url=<?=$url?>">
