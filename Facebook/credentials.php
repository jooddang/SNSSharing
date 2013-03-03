<?php
session_start();

if (empty($_SESSION['fb_access_token'])) {
	//TODO:: alert to user
	echo 'fb token empty';
}
else {
	echo $_SESSION['fb_access_token'];
}
?>
