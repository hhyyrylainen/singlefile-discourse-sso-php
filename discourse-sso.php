<?php
/*
This is single-file SSO client for Discourse.

# Latest version on Github:
https://github.com/ArseniyShestakov/singlefile-discourse-sso-php
# Discourse How-To about setting SSO provider:
https://meta.discourse.org/t/using-discourse-as-a-sso-provider/32974
# Based off paxmanchris example:
https://gist.github.com/paxmanchris/e93018a3e8fbdfced039
*/

define('DB_SERVER', "localhost");
define('DB_NAME', "");
define('DB_USER', "");
define('DB_PASSWORD', "");
define('DB_PORT', "5432");
define('DB_MWSCHEMA', "mediawiki");

define('SSO_DB_TABLE', 'sso_login');

define('SSO_URL_LOGGED', 'https://'.$_SERVER['HTTP_HOST']);
define('SSO_URL_SCRIPT', 'https://'.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']);
define('SSO_URL_DISCOURSE', '<CHANGE_ME>');
// "sso secret" from Discourse admin panel
// Good way to generate one on Linux: pwgen -syc
define('SSO_SECRET', '<CHANGE_ME>');
// Another secret used for sign local cookie
define('SSO_LOCAL_SECRET', '<CHANGE_ME>');
// Seconds before new nonce expire
define('SSO_TIMEOUT', 120);
// Seconds before SSO authentication expire
define('SSO_EXPIRE', 2592000);
define('SSO_COOKIE', '__discourse_sso');
define('SSO_COOKIE_DOMAIN', $_SERVER['HTTP_HOST']);
define('SSO_COOKIE_SECURE', true);
define('SSO_COOKIE_HTTPONLY', true);

// We'll only redirect to Discrouse if script executed directly
if(basename(__FILE__) === basename($_SERVER['SCRIPT_NAME']))
{
	$DISCOURSE_SSO = new DiscourseSSOClient(true);
	$status = $DISCOURSE_SSO->getAuthentication();
	if(false !== $status && true == $status['logged'])
	{
        if(isset($_GET['logout'])){

            $hashedNonce = hash('sha512', $status["nonce"]);

            if($hashedNonce === $_GET['logout']){
                $DISCOURSE_SSO->logoutUser($status["nonce"]);
            } else {
                die("invalid logout request");
            }
            
        } else {
            header('Location: ' . SSO_URL_LOGGED);
        }
	}
	else if(empty($_GET) || !isset($_GET['sso']) || !isset($_GET['sig']))
	{
		$DISCOURSE_SSO->authenticate();
	}
	else
	{
		$DISCOURSE_SSO->verify($_GET['sso'], $_GET['sig']);
	}
}

class DiscourseSSOClient
{
	private $db;
	private $sqlStructure = 'CREATE TABLE IF NOT EXISTS %s (
    id BIGSERIAL PRIMARY KEY,
    nonce TEXT NOT NULL,
    logged SMALLINT NOT NULL,
    name TEXT,
    username TEXT,
    email TEXT,
    admin SMALLINT NOT NULL DEFAULT 0,
    moderator SMALLINT NOT NULL DEFAULT 0,
    expire INTEGER NOT NULL
);';

	public function __construct($createTableIfNotExist = false)
	{
		$this->db = pg_connect("host = ". DB_SERVER . " port = " . DB_PORT . " dbname = " . DB_NAME . " " .
                               "user = " . DB_USER . " password=" . DB_PASSWORD);
        if(!$this->db){
            die("failed to connect to db");
            return;
        }

        pg_query($this->db, "SET search_path TO " . DB_MWSCHEMA);
        
		if($createTableIfNotExist)
			$this->createTableIfNotExist();
		if(rand(0, 10) === 50)
			$this->removeExpiredNonces();
	}

	public function __destruct()
    {
        if($this->db){
            pg_close($this->db);
        }
    }

	public function getAuthentication()
	{
		if(empty($_COOKIE) || !isset($_COOKIE[SSO_COOKIE]))
			return false;


		$cookie_nonce = explode(',', $_COOKIE[SSO_COOKIE], 2);
		if($cookie_nonce[1] !== $this->signCookie($cookie_nonce[0]))
			return false;

		$status = $this->getStatus($this->clear($cookie_nonce[0]));
		if(false === $status)
			return false;

		return $status;
	}

	public function authenticate()
	{
		$nonce = hash('sha512', mt_rand().time());
		$nonceExpire = time() + SSO_TIMEOUT;
		$this->addNonce($nonce, $nonceExpire);
		$this->setCookie($nonce, $nonceExpire);
		$payload = base64_encode(http_build_query(array(
			'nonce' => $nonce,
			'return_sso_url' => SSO_URL_SCRIPT
		)));
		$request = array(
			'sso' => $payload,
			'sig' => hash_hmac('sha256', $payload, SSO_SECRET)
		);
		$url = $this->getUrl($request);
		header('Location: '.$url);
		echo '<a href='.$url.'>Sign in with Discourse</a><pre>';
	}

	public function verify($sso, $signature)
	{
		$sso = urldecode($sso);
		if(hash_hmac('sha256', $sso, SSO_SECRET) !== $signature)
		{
			header('HTTP/1.1 404 Not Found');
			exit();
		}

		$query = array();
		parse_str(base64_decode($sso), $query);
		$query['nonce'] = $this->clear($query['nonce']);

		if(false === $this->getStatus($query['nonce'])){
			header('HTTP/1.1 404 Not Found');
			exit();
		}

		$loginExpire = time() + SSO_EXPIRE;
		$this->loginUser($query, $loginExpire);
		$this->setCookie($query['nonce'], $loginExpire);
		header('Access-Control-Allow-Origin: *');
		header('Location: '.SSO_URL_LOGGED);
	}

    public function logoutUser($nonce)
    {
        $this->removeNonce($nonce);
        $this->unSetCookie();
        header('Location: ' . SSO_URL_LOGGED);
    }

	public function removeNonce($nonce)
	{
        $nonce = pg_escape_string($this->db, $nonce);
        pg_query($this->db, 'DELETE FROM '.SSO_DB_TABLE." WHERE nonce = '" . $nonce . "';");
	}

	private function removeExpiredNonces()
	{
        pg_query($this->db, 'DELETE FROM '.SSO_DB_TABLE.
                 ' WHERE expire < extract(epoch from now());');
	}

	private function addNonce($nonce, $expire)
	{
        $nonce = pg_escape_string($this->db, $nonce);
        pg_query($this->db, 'INSERT INTO '.SSO_DB_TABLE.
                 " (nonce, logged, expire) VALUES ('" . $nonce . "', 0, " . $expire . ");");
	}

	private function getStatus($nonce)
	{
		$return = array(
			'nonce' => $nonce,
			'logged' => false,
			'data' => array(
				'name' => '',
				'username' => '',
				'email' => '',
				'admin'	=> false,
				'moderator'	=> false
			)
		);
        $nonce = pg_escape_string($this->db, $nonce);
		if($result = pg_query($this->db, "SELECT logged, name, username, email, admin, moderator FROM ".SSO_DB_TABLE.
                              " WHERE nonce='$nonce' AND expire  > extract(epoch from now());"))
		{
            while($row = pg_fetch_row($result)) {
				$return['logged'] = intval($row[0]) == 1;
				$return['data']['name'] = $row[1];
				$return['data']['username'] = $row[2];
				$return['data']['email'] = $row[3];
				$return['data']['admin'] = intval($row[4]) == 1;
				$return['data']['moderator'] = intval($row[5]) == 1;
                return $return;                
			}
		}
		return false;
	}

	private function loginUser($data, $expire)
	{
		$isAdmin = $data['admin'] === 'true' ? '1' : '0';
		$isModerator = $data['moderator'] === 'true' ? '1' : '0';

        pg_query($this->db, "UPDATE ".SSO_DB_TABLE."
			SET
				logged = 1,
				expire = ".$expire.",
				name = '".pg_escape_string($this->db, $data['name'])."',
				username = '".pg_escape_string($this->db, $data['username'])."',
				email = '".pg_escape_string($this->db, $data['email'])."',
				admin = '".$isAdmin."',
				moderator = '".$isModerator."'
			WHERE nonce = '".pg_escape_string($this->db, $data['nonce'])."'");        
	}

	private function setCookie($value, $expire)
	{
		setcookie(SSO_COOKIE, $value.','.$this->signCookie($value), $expire, "/", SSO_COOKIE_DOMAIN, SSO_COOKIE_SECURE, SSO_COOKIE_HTTPONLY);
	}

    private function unSetCookie()
    {
		setcookie(SSO_COOKIE, '', time() - 3600, "/", SSO_COOKIE_DOMAIN, SSO_COOKIE_SECURE, SSO_COOKIE_HTTPONLY);
    }

	private function getUrl($request)
	{
		return SSO_URL_DISCOURSE.'/session/sso_provider?'.http_build_query($request);
	}

	private function signCookie($string)
	{
		return hash_hmac('sha256', $string, SSO_LOCAL_SECRET);
	}

	private function clear($string)
	{
		return preg_replace('[^A-Za-z0-9_]', '', trim($string));
	}

	private function createTableIfNotExist()
	{
        $ret = pg_query($this->db, "SELECT EXISTS (SELECT 1 FROM information_schema.tables ".
                        "WHERE table_schema = '". DB_MWSCHEMA ."' AND table_name = '".
                        SSO_DB_TABLE."');");

        $exists = false;

        if($ret){
            while($row = pg_fetch_row($ret)) {
                if($row[0] == 't'){
                    $exists = true;
                }
                break;
            }
        }
        
		if($exists != true)
		{
            pg_query($this->db, sprintf($this->sqlStructure, SSO_DB_TABLE));
		}
	}

	public function dropTable()
	{
		pg_query($this->db, "DROP TABLE IF EXISTS ".SSO_DB_TABLE);
	}
}
