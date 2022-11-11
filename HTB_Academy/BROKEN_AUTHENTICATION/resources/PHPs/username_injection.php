<?php
// declare globals
$user_path = "/dev/shm/users.txt";

// if not exists, create dummy user file
createusers();

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broken Authentication Login - Username injection exercise</title>
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
function showreset() {
?>
    <form action="" method="POST">
	<h2 class="text-center">Reset your password</h2>
	<div class="form-group">
            <input name="passwd" type="password" class="form-control" placeholder="Password" required="required">
	</div>
	<div class="form-group">
            <input name="cpasswd" type="password" class="form-control" placeholder="Confirm Password" required="required">
	</div>

            <button value="reset" name="submit" type="submit" class="btn btn-primary btn-block">Submit</button>
        </div>
    </form>
</div>
<?php
}

function showlogin() {
?>
    <form action="" method="POST">
        <h2 class="text-center">Log in</h2>
        <div class="form-group">
          <!-- name="userid" says that this field will be POSTed as userid -->
            <input name="userid" type="text" class="form-control" placeholder="Username" required="required">
        </div>
        <div class="form-group">
          <!-- name="passwd" says that this field will be POSTed as passwd -->
            <input name="passwd" type="password" class="form-control" placeholder="Password" required="required">
        </div>
        <div class="form-group">
            <button name="submit" value="login" type="submit" class="btn btn-primary btn-block">Log in</button>
        </div>
    </form>
<?php

}

// generate some dummy users
function createusers() {
  global $user_path;
  if (!(file_exists($user_path))) {
    // open the file
    $fh = fopen($user_path, "w");

	  $users = [
      'htbadmin' => 'resetme',
      'htbuser'  => 'htbuser',
      'htbdemo'  => 'resetme',
      'htbguest' => 'resetme',
    ];

    foreach ($users as $u => $p) {
      fwrite($fh, $u.":".$p."\n");
    }
    fclose($fh);
  }
}

function doreset($userid, $passwd) {
  global $user_path;
  $users = file($user_path);

  // opens the file in write mode, this will break if there is concurrency!!
  $fh = fopen($user_path, "w");

  foreach ($users as $line) {
    // explode line into list
    $line = trim($line);
    $list = explode(":", $line);
    // take first element
    $u = array_shift($list);

    // handle passwords that contains a :
    $p = implode(':', $list);

    // check if current line is specific to requested user
    if ($userid === $u) {
      fwrite($fh, $u.":".$passwd."\n");
    } else {
      fwrite($fh, $u.":".$p."\n");
    }
  }
}

function checklogin($userid, $passwd) {
  global $user_path;
  $users = file($user_path);
  foreach ($users as $line) {
    // explode line into list
    $line = trim($line);
    $list = explode(":", $line);
    // take first element
    $u = array_shift($list);

    // handle passwords that contains a :
    $p = implode(':', $list);

    if (($userid === $u) && ($passwd === $p) ) {
      return True;
    }
  }
  return False;
}

if (isset($_POST['submit'])) {
  // check if someone is trying to login
  if ($_POST['submit'] === 'login') {
    if (checklogin($_POST['userid'], $_POST['passwd'])) {
	    echo '<div class="alert alert-primary"><strong>Welcome '.htmlspecialchars($_POST['userid']).'</strong></div>';
    } else {
	    echo '<div class="alert alert-warning"><strong>Wrong credentials</strong></div>';
    }
  // no login, defaults to reset
  } else {
    // pretend you are browsing as htbuser
    $userid = 'htbuser';

    // mimic the logical vulnerability
    if (isset($_REQUEST['userid'])) {
      $userid = $_REQUEST['userid'];
    }
	  echo '<div class="alert alert-primary"><strong>You are resetting password for user '.htmlspecialchars($userid).'</strong></div>';
    // Remove all characters except letters, digits and !#$%&'*+-=?^_`{|}~@.[]
    $clean_passwd = filter_var($_REQUEST['passwd'], FILTER_SANITIZE_EMAIL);

    doreset($userid, $clean_passwd);
  }
}

// to keep everything simple, we show both login and reset on the same page. submit button have a different value for the two calls
showlogin();
showreset();
?>


</body>
</html>                                		