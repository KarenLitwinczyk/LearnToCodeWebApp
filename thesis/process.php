<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');
// header('Content-type: application/json');
$dbms = 'mysql';
$host = 'localhost';
$database = 'klitwinczyk_thesis';
$dsn = "$dbms:dbname=$database;host=$host";
$user = 'klitwinczyk';
$password = 'rollwiththepunches';

if(!isset($_POST['action'])){
	die(json_encode(array("Message"=>"No action given :^(")));
}

try{
	$dbh = new PDO($dsn, $user, $password);
}catch(PDOException $e){
	die(json_encode(array("Message"=>"Connection Failed" . $e->getMessage())));
}

$action = $_POST['action'];
if($action == "signin"){
	if(!hasPostParams(['username', 'password'])){
		die(json_encode(array("Message"=>"Missing required parameters")));
	}
	signin($dbh, $_POST['username'],$_POST['password']);
}elseif($action == "signup"){
	if(!hasPostParams(['username', 'password','displayName'])){
		die(json_encode(array("Message"=>"Missing required parameters")));
	}
	signup($dbh, $_POST['username'], $_POST['password'],$_POST['displayName']);
}


function signIn($dbh,$username, $password){
    session_start();
    $checkCredentials = $dbh->prepare('select password from users where username = :username;');
    $checkCredentials->execute(array(':username'=>$username));
    $result = $checkCredentials->fetch();
    if(password_verify($password, $result[0])){
        if(array_key_exists("loggedIn", $_SESSION)){
	    	if($_SESSION["username"]!= $username){
	        	session_destroy();
	        	$_SESSION["loggedIn"] = true;
	        	$_SESSION["username"] = $username;
	    	}
	    	else{
	      		echo json_encode(array("Message"=>"You are already logged in"));
	    	}
        }else{
	    	$_SESSION["loggedIn"] = true;
	    	$_SESSION["username"] = $username;
	    	echo json_encode(array("Message"=>"You are now signed in!"));
        }
    }else{
		echo json_encode(array("Message"=>"Invalid Username or Password"));

    }
}

function signup($dbh, $username, $password, $displayName){
	$findUsername = $dbh->prepare('select count(*) from users where username = :username;');
	$findUsername->execute(array(':username'=>$username));
	$resFindUsername = $findUsername->fetch();
	echo json_encode(array("Pass"=>$password));
	$passwordHashed = password_hash($password, PASSWORD_BCRYPT);
	if($resFindUsername[0] > 0){
		die(json_encode(array("Message"=>"Username already taken, please pick a new one.")));
	}else{
		$addUser = $dbh->prepare('insert into users (username, password, fullName) values(:username, :password, :displayName);');
		$addUser->execute(array(':username'=>$username, ':password'=>$passwordHashed, ':displayName'=>$displayName));
		$res = $addUser->fetchAll();
		echo json_encode(array("Message"=>"Yay, you are now a registered user!"));
	}
}


function hasPostParams($params){
    foreach($params as $param){
	if(!isset($_POST[$param]))
	    return false;
    }
    return true;

}


?>