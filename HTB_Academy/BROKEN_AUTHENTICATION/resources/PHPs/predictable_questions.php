<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broken Authentication Login - Reset question exercie</title>
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
<?php

/*
 * this dictionary contains proposed questions and expected answers.
 * as you can see, only one is actually guessable.
 * we have three ways to bruteforce:
 * 1) try to send pasta/pizza without reading the question
 * 2) reload the page if the question is not the one we want to try to guess
 * 3) inspect this page behaviour and see if it's possible to always reply to guessable questioin
 *
 * the third one is preferred when possible, the second one should be the second choice and the first way should be avoided when possible.
 */
$htbadmin_questions = array(
  // this one is very easily guessable
	"Do you prefer pizza or pasta?" => "pizza",
	// these ones are "impossible"
	"What city you met your best friend?" => "this question doesn't have a guessable answer",
	"What's your favourite sport team?" => "this question doesn't have a guessable answer",
	"What is your favourite pizza flavour?" => "this question doesn't have a guessable answer",
	"Where is your favourite place for holyday?" => "this question doesn't have a guessable answer"
);

function show_questions($questions) {
	$q = array_rand($questions,1);
?>
<div class="login-form">
    <form action="" method="POST">
	<h2 class="text-center">Reset your password</h2>
	<div class="form-group">
	<input type="hidden" name="question" value="<?php echo $q;?>">
	<input type="hidden" name="userid" value="htbadmin">
	<div class="alert"><strong><?php echo $q;?></strong></div>
        <input name="answer" type="text" class="form-control" placeholder="Answer" required="required">
	</div>

            <button value="answer" name="submit" type="submit" class="btn btn-primary btn-block">Submit</button>
        </div>
<?php
}
?>
<div class="login-form">
<?php

if (isset($_POST['submit'])) {
	if ( (($_POST['userid']) === 'htbadmin') && ($_POST['submit'] === 'answer')) {
		if (strtolower($_POST['answer']) === strtolower($htbadmin_questions[$_POST['question']])) {
			echo '<div class="alert alert-primary"><strong>Congratulation, you could now reset htbadmin password.</div></strong></div>';
			exit;
		} else {
			echo '<div class="alert alert-warning"> <strong>Sorry, wrong answer.</strong></div>';
			show_questions($htbadmin_questions);
			exit;
		}
	} else if (($_POST['userid']) === 'htbadmin') {
		show_questions($htbadmin_questions);
		exit;
	} else if (($_POST['userid']) === 'htbuser') {
		echo '<div class="alert alert-warning"> <strong>You should focus on resetting htbadmin password!</strong></div>';
	} else {
		echo '<div class="alert alert-warning"> <strong>Unknown user.</strong></div>';
	}
}
?>


    <form action="" method="POST">
	<h2 class="text-center">Reset your password</h2>
	<div class="form-group">
            <input name="userid" type="text" class="form-control" placeholder="Username" required="required">
	</div>

            <button value="submit" name="submit" type="submit" class="btn btn-primary btn-block">Submit</button>
        </div>
    </form>
</div>

</body>
</html>                                		
