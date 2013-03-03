<?php
	session_start();

	$token = $_GET['token'];
	$result = $_GET['result'];
	$_SESSION['me2_user_id'] = $_GET['user_id'];
	$_SESSION['me2_user_key'] = $_GET['user_key'];

?>
<script>window.close();</script>

