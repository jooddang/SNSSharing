<?php

session_start();

if (!empty($_GET['access_token'])) {
	$_SESSION['fb_access_token'] = $token = $_GET['access_token'];
}
//echo 'tok[' . $_GET['access_token'] . ']['. $_GET['code'] .']';
?>

<html>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<head>
	<script>

	function loadMe() {
		var url = document.URL;

		//TODO: client_id, client_secret must be CHANGED!! facebook app client id issued by facebook.
		var client_id = 'YOUR_ID'; 
		var client_secret = 'YOUR_SECRET';
		var permissions = 'publish_stream';

		var auth = 'http://www.facebook.com/dialog/oauth?client_id=' +client_id + '&redirect_uri='+url+'&response_type=token&scope='+permissions;

		try {
			if (url.indexOf('?code=') > 0) {
				var codeIndex = url.indexOf('?code=');
				var code = url.substring(codeIndex + 6);
				
				var nextPageURL = url;

				var graphAuth = 'https://graph.facebook.com/oauth/access_token?client_id='+client_id + '&redirect_uri='+nextPageURL+ '&client_secret=' + client_secret + '&code=' + code;// + '&type=client_cred';
				window.location.href = graphAuth;
			}
			
			else if (url.indexOf('access_token=') > 0) {
				var re = /access_token=[^&]+/;
				var token = re.exec(url)[0];
				if (token.indexOf('token=') >0 ) {
					token = token.substring(token.indexOf('=')+1);
					<?php
					if (empty($_GET['access_token']) && empty($_GET['code'])) {
					?>
						var h = "?" + window.location.hash.substring(1);
						if (url.indexOf('#')) {
							var redirect = url.substring(0, url.indexOf('#'));
							window.location = redirect + h;
						}
					<?php
					}
					else if (!empty($_GET['access_token']) && empty($_GET['code'])) {
						echo 'window.close();';
					}
					?>
				}
			}
			else if (url.indexOf('?error') > 0) {
				//alert('rejected!!');
			}
			else {
				// starts from here.
				window.location.href=auth;
			}
		}
		catch (e) {
			window.location.href=auth;
		}
	}
	</script>
</head>
<body onLoad=loadMe();>

</body>

</html>
