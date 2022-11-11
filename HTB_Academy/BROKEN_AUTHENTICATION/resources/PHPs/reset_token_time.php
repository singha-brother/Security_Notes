<?php
// common header, can skip until READ_HERE mark
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broken Authentication Login - Reset token time()</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script> 
<style>
	.login-form {
		width: 500px;
    	margin: 50px auto;
	}
    .login-form form {
    	margin-bottom: 15px;
        background: #f7f7f7;
        box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
        padding: 30px;
    }
    .login-form h2 {
        margin: 0 0 15px;
    }
    .form-control, .btn {
        min-height: 38px;
        border-radius: 2px;
    }
    .btn {        
        font-size: 15px;
        font-weight: bold;
    }
</style>
</head>
<body>
<div class="login-form">
<?php
// READ_HERE

// where we will save our token
$token_file = "/dev/shm/token.txt";

// if file does not exists, create a token for this test session
if (!(@file_exists($token_file))) {
  // get time in seconds
	$time = intval(microtime(true));

  // calculate token md5 hash
	$token = md5($time);

  // create and write tokenfile
  $fh = fopen($token_file, "w") or die("Unable to open file!");
  fwrite($fh, $token);
  fclose($fh);
}

// read token from file
function get_token($file) {
	$fh = fopen($file, "r");
	$token = fread($fh, filesize($file));
  // we shouldn't have any \r or \n, just to be safe
  $token = str_replace(PHP_EOL, '', $token);
	fclose($fh);
	return $token;
}

// if we have a POST as check that contain a token field, and the field is valid reply with "Great work", else just return "Wrong token"
if (isset($_POST['submit'])) {
	if ($_POST['submit'] === 'check') {
		$valid = get_token($token_file);
		if ($valid === $_POST['token']) {
			echo '<div class="alert alert-primary"> <strong>Great work!</strong></div>';
			exit;
		} else {
			echo '<div class="alert alert-warning"> <strong>Wrong token.</strong></div>';
		}
	}
}
?>
    <form action="" method="POST">
	<h2 class="text-center">Input a valid token</h2>	
        <div class="form-group">
            <input name="token" type="text" class="form-control" placeholder="Token" required="required">
        </div>

            <button value="check" name="submit" type="submit" class="btn btn-primary btn-block">Check</button>
        </div>
    </form>
</div>
</body>
</html>                                		