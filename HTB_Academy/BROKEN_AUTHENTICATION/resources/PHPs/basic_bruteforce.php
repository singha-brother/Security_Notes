<!DOCTYPE html>
<!-- starting standard HTML, you can safely skip until the end -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broken Authentication Login - Basic bruteforce example</title>
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
// if PHP received a POST with a userid field
if (isset($_POST['userid'])) {
  // if given userid is equal to testuser, and passwd field is testpass
	if (($_POST['userid'] === "testuser") && ($_POST['passwd'] === "testpass")) {
    // say welcome
		echo '<div class="alert alert-primary"><strong>Welcome, testuser!</strong> </div>';
	} else {
    // reply with invalid credential message
		echo '<div class="alert alert-warning"><strong>Invalid credential.</strong> </div>';
	}
}
?>
<!-- standard login form -->
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
            <button type="submit" class="btn btn-primary btn-block">Log in</button>
        </div>
    </form>
</div>
</body>
</html>