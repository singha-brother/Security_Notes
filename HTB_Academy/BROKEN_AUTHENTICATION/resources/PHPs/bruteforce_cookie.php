<?php
// declare globals
$cookie_path = "/dev/shm/cookie.txt";
$cookie_len  = 5;

// if not exists, create dummy cookie file
createcookie();

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broken Authentication Login - Cookie bruteforce exercise</title>
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

// generate a random string
function genrand() {
  global $cookie_len;
  // lower, upper, digit
  //$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  // lower, digit
  $characters = '0123456789abcdefghijklmnopqrstuvwxyz';

  $rand= '';
          
  for ($i = 0; $i < $cookie_len; $i++) {
    $index = rand(0, strlen($characters) - 1);
    $rand.= $characters[$index];
  }
  return $rand;
}


// read our *master cookie*
function getcookie() {
  global $cookie_path;
  // this if should never be true
  if (!(file_exists($cookie_path))) {
    createcookie();
  }

  // read the file
  $c = file_get_contents($cookie_path);
  // remove eventual newlines
  $c = trim($c);

  return $c;
}

// generate a *master cookie* that will be used as test match, mimic a bruteforce success
function createcookie() {
  global $cookie_path;
  if (!(file_exists($cookie_path))) {
    // open the file
    $fh = fopen($cookie_path, "w");

    // write a random string
    fwrite($fh, genrand());

    // finally close
    fclose($fh);
  }
}

// if a our cookie is set, check if it's valid against generated one at createcookie()
if (isset($_COOKIE['HTBSESS'])) {
  // if it matches with our generated one
  if ($_COOKIE['HTBSESS'] == getcookie()) {
    echo '<div class="alert alert-primary"><strong>You have successfully bruteforces the cookie!</strong></div>';
  } else {
    echo '<div class="alert alert-warning"><strong>Not yet...</strong></div>';
  }
} else {
  echo '<div class="alert alert-warning"><strong>Start by giving you a cookie...</strong></div>';
  setcookie("HTBSESS", genrand());
}

?>


</body>
</html>                                		