<!DOCTYPE html>
<!-- starting standard HTML, you can safely skip until the end -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broken Authentication Login - Basic password policy example</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
<style>
	.login-form {
		width: 340px;
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
<!-- ending standard HTML, you can safely skip until the end -->
<div class="login-form">
<?php
function password_policy($p) {
  $required = 0x1; // lower
  $required = 0x3; // lower and upper
  $required = 0x7; // lower, upper and digit
  $required = 0xf; // lower, upper, digit and special
  $required = 0xb; // lower, upper, and special
    

  if (preg_match('/[a-z]/', $p)) { $lower   = 0x1; }
  if (preg_match('/[A-Z]/', $p)) { $upper   = 0x2; }
  if (preg_match('/[0-9]/', $p)) { $digit   = 0x4; }
  if (preg_match('/[^\w]/', $p)) { $special = 0x8; }

  $complexity = $upper + $lower + $digit + $special;

  if ($complexity >= $required) {
    return True;
  } else {
    return False;
  }       
}       

// if PHP received a POST with a submit field
if (isset($_POST['submit'])) {
  // we ignore any other field because we are testing password policy
	if (password_policy($_POST['passwd'])) {
    // say welcome
		echo '<div class="alert alert-primary"><strong>Thanks for registering, you should receive an email shortly.</strong> </div>';
	} else {
    // reply with invalid credential message
		echo '<div class="alert alert-warning"><strong>Your password doesn\'t meet complexity requirements.</strong> </div>';
	}
}
?>
<!-- standard login form -->
    <form action="" method="POST">
        <h2 class="text-center">Register</h2>
        <div class="form-group">
          <!-- name="userid" says that this field will be POSTed as userid -->
            <input name="userid" type="text" class="form-control" placeholder="Username" required="required">
        </div>
        <div class="form-group">
          <!-- name="email" says that this field will be POSTed as email -->
            <input name="email" type="text" class="form-control" placeholder="E-mail" required="required">
        </div>
        <div class="form-group">
          <!-- name="passwd" says that this field will be POSTed as passwd -->
            <input name="passwd" type="password" class="form-control" placeholder="Password" required="required">
        </div>
        <div class="form-group">
          <!-- name="cpasswd" says that this field will be POSTed as cpasswd -->
            <input name="cpasswd" type="password" class="form-control" placeholder="Confirm Password" required="required">
        </div>
        <div class="form-group">
            <button name="submit" value="submit" type="submit" class="btn btn-primary btn-block">Register</button>
        </div>
    </form>
</div>
</body>
</html>