<?php 
	if (isset($_GET['ping'])) 
		die('pong'); 

	if (isset($_GET['i'])) {
		header('Location: http://suigintou.desudesudesu.org/4scrape/img/' . $_GET['i']);
		die();
	}

	if (isset($_GET['stats']))
		die();

	$pubkey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8QpxTBWWQZz0y+g+GKe\niNHSnpIwv0c8p4AJgXYrvukcwHx/+GsdhjGSgoGcESY3rsLp2SwW5QVYI1rp1WP9\nlWkIfbPuuNy51diUNyi/RCnyP6UTlu5a4rkUUDMrtyXJiOYfN4DNBxA50cgV9r0a\nCWnIyd4UOUn+cJq4/u6YkjB2nPDI6p8+qOjd1+KM/S6U94FATpxHpEc5ApiauEnY\n1cazIBvqRwFiSZkPWrbvLV5lS1QlbmwhxvFV6QGXoGbH7BWlnYJy55rtXzxsoEwP\nHpgd4frrPi6K1yLV2ROk7s69Bffwo35ZesiSWmSJmhcfqZrRC5ZYAg5lpteHT0Cx\nIQIDAQAB\n-----END PUBLIC KEY-----";
	$openssl_test_enc64 = "AFelPmVmrjIysUhudEjyCIVGwd0lbhymek9Na/xaNoZqILWqt4aaaBLLipEKX1KZ ZM/BLSjbc6A8dJSSoAdq082bHGn8Qz2vlucnv1yfbLPHIEFF99roHOA9o6d6qg0c gF2xKe543Pevtv5q0128vW+gIeBk8+4E0QVqxZ9pb9myS9jqT0kLZtIgf7H5GwnV f8k3UzygnqZJexvBOK5OY+cNVQtt0gh0Su9ochDmeDrgWTebDvONHlVdaPSqAFO6 oaOC1TqocjMuH5yIac9sC0IdYz760ykGciKzHSNbZH43m7/06K34+FDz5ix58LgN FpuzyDTslsmbKXTeT+trfQ==";
	$suigintou_laugh = "data:image/gif;base64,R0lGODlhKAAwAMQUAAAAABUOFi0eMSooLDQzNTxERkAxRFhQTXFkfJwwSrZOZ6CVj6Wtr8S9z97Kv8HHx/nw6/f0+vP7/vj4+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQJDAAUACwAAAAAKAAwAAAF/iAljmRpnmiqrmzrvnAszzQK3EDd3oKSCDddCiAA4oo54YhAIN4QjQaCB2AKCYMmABHpQiPTaraGpQy2UW8kOh2YCTTmGfqVNsBSQBZeO0u/dH8Nekp+YTcLOFCEOmcAeQAQAA6RaDdufU+DEJydj2GYNANhgw4QCQkQlINboTOjWzcODqizT600OY6QC7OJloRJOyM4N6zFxsjEK8UUN1oRiNIA0VVBzcxNWU53Nz43a05Y1ipJellnAgYBjwASN++DAQZA6GciwiSXe01F8zcPJEh4cGMdEiZYHNlAOGBPFQH/ADwgCMBgEzn88uGrMk5MEwPr6GkhoG6eAY+X75gEKUHOWUojRLLAFNDRXJMTOcxVFDDQkZ6EOAYEVLcyJzN6DJLmpFlkABBnSRkQhUGEQYGrAAIU0eIUIoCrV5++uFHggINERU5O3Amk14GvGlkAYADgwFt6J3HgrfuWrgx3FIHkFVjQicR3M+ayhceYCFG/fwWDhEmYB8iTYsdKZkBv7jt3dNVxxhy3nOCAneF9JmJgIGnNgl1/HSgwYIGKqB2XxmnEAGcjYMFa5kzFRdHOQCZohTjByVSXxok9vRGAXVbrzjLvZkZMKw92y5R0N+JVPE7vRMCbZxkgwY0E6tfrI79dvOHM8vXhkxECACH5BAUMABQALAAAAAAoADAAAAX+ICWOZGmeaKqubOu+cCyfQA3Mby0oiVDjK4DAZxvegCUCQVhDNBoIHUCJpBAGSwAiwnVGolMs8EoZaJ/dyDM6KBNwSrPTC218oQDsG2iGeud+DXlVZQB4Ngs2ToNIZoZgEwAOAJGLjDiOixObnI81bXxggg4JpQmTglqgmFFgpKaTWqo4N46HC6WJZ58URy2+NjWpwcLEI74owb1TNRE1urrOzDfKQUtYTHY1PM2CPlfMKkd5WGYCBgGGABI17IIBBj7lZiLIx+RKS0PwNQ8SEg9qoDOSb4CjZAX1TBHAD8CDgAAGLomjZ4mJGnEwYjOALl4WAufgGQiTRaG9Xhbul+UBWQQLESHgfqA82avmsngAHa00aGOAv3MyqQWJx6AoNQEgBQzw0asoA6AwhDAoQBVAgCEl9wGgSpVpjq0HHCQaMvJfRCMLHBzYSlMcAwAH1sYbaWMu3LVvZayD6IOu2YhMHLKbAeBtPCIQ+QLNq7cvx5d/hXAc6TWHYwbxBLcLeA4z5bbJ+vrL3A+iZICfLfdFLdgfQIARRwupHISIAcw+Crx+XUAyZikugmYewpWrEajLgh9jWmPCVYYTmFcGLe5YgHRW0x0jRMIqEYbUkXjXoZ37xavkwwOxmqBGgvLmSwSmHX858PoX68kIAQA7";
	$openssl_test_enc = base64_decode($openssl_test_enc64);
	$openssl_test_plain = "success\n";
	$test_file_host = 'suigintou.desudesudesu.org';
	$test_file_path = '/bg.png';
	$test_file_md5 = 'fcffab9aa7a993f8c7d8e9d44914fe5d';

	/* IIS is really gay and doesn't set REQUEST_URI */
	if (!isset($_SERVER['REQUEST_URI'])) {
		$dodgy_iis_bullshit = true;
		$_SERVER['REQUEST_URI'] = $_SERVER['PHP_SELF'];
	}

	/* $basepath is the physical base */
	$basepath = dirname(__FILE__);

	/* $baseuri is the virtual base */
	$baseuri = implode('/', explode('/', $_SERVER['REQUEST_URI'], -1));
	$fileuri = explode('?', substr($_SERVER['REQUEST_URI'], 1 + strlen($baseuri)));
	$fileuri = $fileuri[0];

	if (substr($fileuri, 0, 1) == '/')
		$fileuri = substr($fileuri, 1);

	if (substr($baseuri, 0, 1) != '/')
		$baseuri = '/' . $baseuri;

	if (substr($baseuri, -1) != '/')
		$baseuri = $baseuri . '/';

	/* Get the server name, then strip off or add on the port
	 * number as needed */
	$server_name = $_SERVER['SERVER_NAME'];
	$server_name_noport = $_SERVER['SERVER_NAME'];
	$colon = strpos($server_name, ':');

	if (false === $colon)
		$server_name .= ':' . $_SERVER['SERVER_PORT'];
	else
		$server_name_noport = substr($server_name, 0, $colon);

	$fulluri = 'http://' . $server_name . $baseuri . $fileuri;
	$version = 1;
	
	function sanitize_js($s) {
		return str_replace(array("\\", "'", "\n"), array("\\\\", "\\'", "\\n"), $s);
	}

	function pre_test($test_desc) {
		ob_start();
		echo('Testing ' . $test_desc . '... ');
	}

	function post_test($success, $critical, $message, $extra = array()) {
		$message = $message;

		if (!$success) {
			if ($critical) {
				$out = "<b><font color='red'>Failed!</font></b><br/>$message<br/>";
			}
			else
				$out = "<b><font color='yellow'>Warning!</font></b><br/>$message<br/>";
			$success = '0';
		}
		else {
			$out = "<b><font color='green'>Ok!</font></b><br/>";
			$success = '1';
		}

		$out = sanitize_js($out);
		$desc = sanitize_js(ob_get_contents());
		ob_end_clean();
		die("{'success':$success,'msg':'$out','desc':'$desc'}");
	}

	if (isset($_GET['test_php_version'])) {
		pre_test('your PHP version');
		$res = (version_compare(PHP_VERSION, '5.2.0') === 1);
		post_test($res, false, "Meimei is currently only tested with PHP 5.2. You might run into some weird errors running on your earlier version.");
	}

	if (isset($_GET['test_openssl_extension_installed'])) {
		pre_test('if you have the OpenSSL extension installed');
		$res = (function_exists('openssl_public_decrypt'));
		post_test($res, false, "Let's check if there's a usable OpenSSL binary...");
	}

	if (isset($_GET['test_openssl_extension_works'])) {
		pre_test('if OpenSSL extension works properly');
		$tmp = '';
		if (false === openssl_public_decrypt($openssl_test_enc, $tmp, $pubkey)) {
			$res = false;
			$msg = "openssl_public_decrypt returned an error -- the keys are broken or something";
		}
		else {
			$res = ($openssl_test_plain == $tmp);
			$msg = "the unencrypted data didn't match the expected value";
		}

		post_test($res, false, $msg);
	}

	if (isset($_GET['test_openssl_binary_installed'])) {
		pre_test('if you have a working OpenSSL binary installed');

		if ($dodgy_iis_bullshit) {
			post_test(false, false, "Not even going to try on IIS.");
		}
		else {
			$openssl_path = exec('which openssl', $unused, $res);
			$res = ($res == 0);
			post_test($res, false, "Ugh, you have no support for OpenSSL, which means no automate updates or mirror verification.");
		}
	}

	if (isset($_GET['test_openssl_binary_works'])) {
		pre_test('if external openssl works properly');

		$htmp_key_p = tempnam(sys_get_temp_dir(), 'meimei');
		$htmp_data_p = tempnam(sys_get_temp_dir(), 'meimei');

		$htmp_key = @fopen($htmp_key_p, 'w+');
		$htmp_data = @fopen($htmp_data_p, 'w+');

		if (false === $htmp_key || false === $htmp_data) {
			$ret = false;
			$msg = "unable to create a temporary files to dump the public key and data to";
		}
		else {
			fwrite($htmp_key, $pubkey);
			fclose($htmp_key);

			fwrite($htmp_data, $openssl_test_enc);
			fclose($htmp_data);

			$htmp_key_p = escapeshellarg($htmp_key_p);
			$htmp_data_p = escapeshellarg($htmp_data_p);

			$tmp = shell_exec("openssl rsautl -verify -in $htmp_data_p -inkey $htmp_key_p -pubin");
			
			$ret = ($openssl_test_plain == $tmp);
			$msg = "the unencrypted data didn't match the expected value<br/>(got `$tmp')";
		}

		post_test($ret, false, $msg);
	}
		
	if (isset($_GET['test_dns_capability'])) {
		pre_test('if I can resolve Suigintou\'s address?');
		$res = (gethostbyname('suigintou.desudesudesu.org') == '87.98.229.30');
		post_test($res, true, "Huh. I can't resolve the address, which means you have no internet connectivity, PHP is doing something weird, or your DNS is set up strangely.");
	}

	if (isset($_GET['test_dns_resolves'])) {
		pre_test('if I can resolve your SERVER_NAME');
		$res = (gethostbyname($server_name_noport) != $server_name_noport);
		post_test($res, true, "You have to have a host name which is resolvable to an IP address, otherwise no one will be able to access your mirror. The hostname detected was {$server_name_noport}");
	}

	if (isset($_GET['test_dns_valid'])) {
		pre_test('if your server name resolves to your IP address');
		$res = (gethostbyname($server_name_noport) == $_SERVER['SERVER_ADDR']);
		post_test($res, true, "Your hostname is resolvable, but it does not resolve to the IP address reported by the webserver. Wtf?");
	}

	if (isset($_GET['test_safe_mode'])) {
		pre_test('if safe_mode is disabled');
		$res = (!ini_get('safe_mode'));
		post_test($res, false, "It's on. You might consider turning it off if there are problems.");
	}

	if (isset($_GET['test_allow_url_fopen'])) {
		pre_test('if allow_url_fopen is enabled');
		$res = (ini_get('allow_url_fopen'));
		post_test($res, true, "Whoops -- the current version of Meimei requires allow_url_fopen to be turned on. I'll fix this in the future, but you'll have to change it (depends on how you're running PHP -- I'll try to do it automatically in the future).");
	}

	if (isset($_GET['test_download_rate'])) {
		$test_file_time = 0;
		$test_file_len = 0;

		function microtime_float() {
			list($usec, $sec) = explode(" ", microtime());
			return ((float) $usec + (float) $sec);
		}

		function test_fopen() {
			global $test_file_host, $test_file_path, $test_file_md5, $test_file_time, $test_file_len;
			$time_start = microtime_float();

			$fh = fopen('http://' . $test_file_host . $test_file_path, 'r');

			if (false === $fh)
				return 'Was unable to open remote stream to fetch the remote file.';

			$data = '';
			$test_file_len = 0;

			while (!feof($fh)) {
				$tmp = fread($fh, 8192);
				$test_file_len += strlen($tmp);

				if (false === $tmp)
					return 'Some error during fread - unable to fetch file.';

				$data .= $tmp;
			}

			if ($test_file_md5 !== md5($data))
				return 'MD5 mismatch - data fetched is invalid.';

			$test_file_time = microtime_float() - $time_start;

			return false;
		}

		pre_test('if I can fetch data from Suigintou?');
		$msg = test_fopen();
		$ret = (!$msg);
		post_test($ret, true, $msg);
	}

	if (isset($_GET['test_upload_rate'])) {
		pre_test('if Suigintou can fetch data from me?');
		$ping_url = 'http://suigintou.desudesudesu.org/meimei/api?a=ping&ip=' . $_SERVER['REMOTE_ADDR'] . '&url=' . urlencode($fulluri . '?ping');
		$test = file_get_contents($ping_url);
		$ret = ('success' == $test);
		post_test($ret, true, "for some reason, your server is inaccessible to outside connections: `$test' was the response from `$ping_url'");
	}

	if (isset($_GET['test_dir_writable'])) {
		pre_test('if the directory is writable');
		$ret = (is_writable('.'));
		post_test($ret, false, "you need to make the current directory writable");
	}

	if (isset($_GET['install'])) {
### INSTALL START ###
		error_reporting(0);

		$serialized_cfg = str_replace(array("\\", "\"", "\n"), array("\\\\", "\\\"", "\\n"), serialize($_POST));	

		if (substr($_POST['cache'], -1) != '/') 
			$_POST['cache'] = $_POST['cache'] . '/';

		$cachedir = $_POST['basedir'] . $_POST['cache'];

		$dirs_to_make = array(
			$cachedir, 
			$cachedir . 'w', 
			$cachedir . 'wg', 
			$cachedir . 'preview',
			$cachedir . 'thumb',
			$cachedir . 'thumb/w',
			$cachedir . 'thumb/wg'
		);

		foreach ($dirs_to_make as $dir) 
			if (!file_exists($dir)) {
				if (false === mkdir($dir, 0777))
					die('{"success":0,"error":"unable to create cache directory (' . $dir . ')"}');
			}
			else if (!is_writable($dir))
				die('{"success":0,"error":"directory exists, but is not writable (' . $dir . ')"}');

		$bw_periods = array(
			'd' => 60 * 60 * 24,
			'w' => 60 * 60 * 24 * 7,
			'm' => 60 * 60 * 24 * 7 * 4
		);

		if (!isset($bw_periods[$_POST['bwp']]))
			die('{"success":0,"error":"unknown bandwidth period ' . $_POST['bwp'] . '"}');

		$bw_period = $bw_periods[$_POST['bwp']];
		$bw_max = ((int) $_POST['bw']) * 1024 * 1024;
		$disk_max = ((int) $_POST['disk']) * 1024 * 1024;
		$update = ($_POST['update'] == '1');
		$openssl_mode = $_POST['openssl_mode'];

		$stats = array(
			'file_count' => 0,
			'disk_used' => 0,
			'bandwidth_used' => 0,
			'bandwidth_used_total' => 0,
			'bandwidth_reset' => time() + $bw_period, 
			'last_request' => 0,
			'num_requests' => 0
		);

		$statsfile = $cachedir . '.stats';
		$lockfile = $cachedir . '.lock';

		if (file_exists($statsfile))
			$stats = array_merge($stats, unserialize(file_get_contents($statsfile)));
		
		if (false === touch($lockfile))
			die('{"success":0,"error":"unable to create lockfile"}');

		if (false === file_put_contents($statsfile, serialize($stats)))
			die('{"success":0,"error":"unable to init stats file"}');

		if (false == file_put_contents($cachedir . '.htaccess', 'Options -Indexes'))
			die('{"success":0,"error":"unable to write to .htaccess file"}');

		ob_start();
?>
<?php echo '<?php'; ?>
	$CONFIG = array(
		'get_var' => 'i',
		'validation_regex' => '#^(w/|wg/|preview/)?[0-9]+\.(jpg|gif|png)$#i',
		'cache_dir' => '<?php echo $cachedir; ?>',
		'cache_uri' => '<?php echo 'http://' . $server_name .  $baseuri . $_POST['cache']; ?>',
		'serve_method' => 'redirect',
		'remote_base' => 'http://suigintou.desudesudesu.org/4scrape/img/',
		'lock_file' => '.lock',
		'stats_file' => '.stats',
		'cache_max_filecount' => 0, 
		'cache_max_diskspace' => <?php echo $disk_max; ?>, 
		'bandwidth_max' => <?php echo $bw_max; ?>,
		'bandwidth_period' => <?php echo $bw_period; ?>,
		'serialized_cfg' => '<?php echo $serialized_cfg; ?>'
	);

	if (defined('DUMP_CONFIG'))
		return $CONFIG;

	ini_set('display_errors', 'on');
	error_reporting(E_ALL);

	function report_error($reason) {
		global $CONFIG;
		if (isset($_GET[$CONFIG['get_var']]))
			header('Location: ' . $CONFIG['remote_base'] . $_GET[$CONFIG['get_var']]);
		die($reason);
	}
	
	if (isset($_GET['stats'])) {
		$stats = cache_get_stats();
		$file_space = number_format($stats['disk_used'] / 1024 / 1024, 1);
		$bandwidth_used = number_format($stats['bandwidth_used'] / 1024 / 1024, 1);
		$bandwidth_reset = date('r', $stats['bandwidth_reset']);
		$last_request = date('r', $stats['last_request']);

		header('Content-Type: text/plain');
		die("{$stats['file_count']} file(s), {$file_space}MB disk used\r\n{$stats['num_requests']} requests, {$bandwidth_used}MB bandwidth used\r\n{$bandwidth_reset}\r\n{$last_request}");
	}

	<?php if ($update) { ?>
		$pubkey = '<?php echo $pubkey; ?>';

		<?php if ($openssl_mode == 'extension') { ?>
			function meimei_openssl_verify($key, $data) {
				$tmp = '';
				openssl_public_decrypt($data, $tmp, $key);
				return $tmp;
			}
		<?php } else if ($openssl_mode == 'binary') { ?>
			function meimei_openssl_verify($key, $data) {
				$htmp_key_p = tempnam(sys_get_temp_dir(), 'meimei');
				$htmp_data_p = tempnam(sys_get_temp_dir(), 'meimei');

				$htmp_key = @fopen($htmp_key_p, 'w+');
				$htmp_data = @fopen($htmp_data_p, 'w+');

				if (false === $htmp_key || false === $htmp_data)
					return false;

				fwrite($htmp_data, $data);
				fclose($htmp_data);

				fwrite($htmp_key, $pubkey);
				fclose($htmp_key);

				$htmp_key_p = escapeshellarg($htmp_key_p);
				$htmp_data_p = escapeshellarg($htmp_data_p);

				return shell_exec("openssl -rsautl -verify -in $htmp_data_p -inkey $htmp_key_p -pubin");
			}
		<?php } else { ?>
			function meimei_openssl_verify($key, $data) {
				return false;
			}
		<?php } ?>

		if (isset($_GET['update'])) {
			if ($_SERVER['REMOTE_ADDR'] != '87.98.229.30')
				report_error('update from invalid host');

			$data = meimei_openssl_verify($pubkey, $_POST['code']);

			if (false === $data)
				die('unable to verify authenticity of update');

			echo(eval($data));
			die();
		}
	<?php } ?>


	if (!isset($_GET[$CONFIG['get_var']]))
		report_error('no file requested');

	$i = $_GET[$CONFIG['get_var']];
	if (!preg_match($CONFIG['validation_regex'], $i))
		report_error('invalid file requested');
	$path = $CONFIG['cache_dir'] . $i;

	function serve_set_headers($i) {
		$mime_types = array(
			'jpg' => 'image/jpeg',
			'gif' => 'image/gif',
			'png' => 'image/png'
		);

		header("Content-type: {$mime_types[substr($i, -3)]}");
		header("Content-disposition: inline; filename=\"$i\"");
	}

	function serve_redirect($i, $path) {
		global $CONFIG;
		header('Location: ' . $CONFIG['cache_uri'] . $i);
	}

	function cache_fopen_remote($i, $path) {
		global $CONFIG;
		$sh = fopen($CONFIG['remote_base'] . $i, 'rb');

		if (false === $sh)
			report_error('unable to open remote stream');

		$temp_path = $path . '.partial';
		$fh = fopen($temp_path, 'w+');

		if (false === $fh)
			report_error('unable to open file for caching');

		# Don't do concurrent writes
		$would_block = false;
		if (false === flock($fh, LOCK_EX + LOCK_NB, $would_block)) 
			report_error('unable to lock local file for writing');

		if ($would_block) 
			report_error('multiple fetch requests for same file');

		$length = 0;

		serve_set_headers($i);

		while (!feof($sh)) {
			$tmp = fread($sh, 8192);
			
			if (false === $tmp)
				return;

			if (false === fwrite($fh, $tmp))
				report_error('error writing data to cache');

			echo($tmp);
			$length += strlen($tmp);
		}

		# Need to close the file handle before we can move it on IIS.
		fclose($fh);
		fclose($sh); # and for good measure.

		# Now actually move the file
		if (false === rename($temp_path, $path))
			report_error('error moving partial file to correct path');
	
		return $length;
	}

	function cache_lock($mode) {
		global $CONFIG;
		$lp = fopen($CONFIG['cache_dir'] . $CONFIG['lock_file'], 'rb');

		if (false === $lp)
			report_error('unable to open lock file');

		if (false === flock($lp, $mode))
			report_error('unable to lock file');

		return $lp;
	}

	function cache_get_stats() {
		global $CONFIG;
		$lp = cache_lock(LOCK_SH);


		$data = file_get_contents($CONFIG['cache_dir'] . $CONFIG['stats_file']);

		if (false === $data)
			report_error('unable to read cache stats from file');

		fclose($lp);
		return unserialize($data);
	}

	function cache_update($stats, $len) {
		global $CONFIG;
		$lp = cache_lock(LOCK_EX);

		if ($len > 0) {
			$stats['file_count'] += 1;
			$stats['disk_used'] += $len;
			$stats['last_request'] = time();
			$stats['num_requests'] += 1;
			$stats['bandwidth_used'] += $len * 2;
			$stats['bandwidth_used_total'] += $len * 2;
		}

		if (false === file_put_contents($CONFIG['cache_dir'] . $CONFIG['stats_file'], serialize($stats)))
			report_error('unable to write cache stats to file');

		fclose($lp);
	}
	
	$stats = cache_get_stats();

	if ($stats['bandwidth_reset'] < time()) {
		$stats['bandwidth_reset'] = time() + $CONFIG['bandwidth_period'];
		$stats['bandwidth_used'] = 0;
		@file_put_contents($CONFIG['cache_dir'] . '.htaccess', 'Options -Indexes');
	}

	if ($CONFIG['bandwidth_max'] > 0 && $stats['bandwidth_used'] > $CONFIG['bandwidth_max']) {
		/* unable to serve */
		@file_put_contents($CONFIG['cache_dir'] . '.htaccess', "Order Allow,Deny\nDeny from All");
		report_error('mirror out of bandwidth');
	}

	if (file_exists($path)) {
		$stats['num_requests'] += 1;
		$stats['last_request'] = time();
		$stats['bandwidth_used'] += filesize($path);
		$stats['bandwidth_used_total'] += filesize($path);
		cache_update($stats, 0);

		serve_redirect($i, $path);
	}
	else {
		if ($CONFIG['cache_max_filecount'] > 0 && $stats['file_count'] > $CONFIG['cache_max_filecount'])
			report_error('no more space in cache -- too many files');

		if ($CONFIG['cache_max_diskspace'] > 0 && $stats['disk_used'] > $CONFIG['cache_max_diskspace'])
			report_error('no more space in cache -- disk filled');

		$len = cache_fopen_remote($i, $path);

		cache_update($stats, $len);
	}
<?php echo '?>'; ?>
<?php
		$new_file = ob_get_contents();
		ob_end_clean();

		if (false === $new_file)
			die('{"success":0,"error":"unable to generate script"}');

		if (false == ($fh = fopen(__FILE__, 'w')))
			die('{"success":0,"error":"unable to open self for writing"}');

		if (false == (fwrite($fh, $new_file)))
			die('{"success":0,"error":"unable to write to self"}');

		fclose($fh);

		die('{"success":1}');
### INSTALL STOP ###
	}
?>
<html>
<head>
	<script type="text/javascript" src="http://code.jquery.com/jquery-latest.js"></script>
	<link rel="stylesheet" type="text/css" href="http://suigintou.desudesudesu.org/4scrape/css/style.css"></link>
	<title>Meimei - Configuration</title>
</head>
<body>
<table width="100%" height="100%"><tr><td align="center" valign="middle">
	<div id="tests" style="font-size: x-small">
		<img src="<?php echo $suigintou_laugh; ?>" style="border: 0px"/><br/>
		<b>Examining your system configuration...</b><br/>
	</div>
	<div id="config" style="display: none">
		<h1 style="display: inline"><a href="http://suigintou.desudesudesu.org/4scrape/index" class="clean">4scrape</a></h1><br/>
		<h2 style="display: inline">Meimei Configuration</h2><br/>
		<table>
			<tr>
				<th colspan="2"><hr/></th>
			</tr>
			<tr>
				<th>Script Location</th>
				<td><input type="hidden" name="uri" id="uri"/><div id="d_uri"></div></td>
			</tr>
			<tr>
				<th>Cache Directory</th>
				<td><input type="hidden" name="basedir" id="basedir"/><div id="d_basedir"></div><input type="text" name="cache" id="cache" value=".meimei/"/><div id="not_writable"></div></td>
			</tr>
			<tr>
				<th>Your Email</th>
				<td><input type="text" name="email" id="email"/></td>
			</tr>
			<tr>
				<th>Disk (MB)</th>
				<td><input name="disk" id="disk" type="text" value="4096"/></td>
			</tr>
			<tr>
				<th>Bandwidth (MB)</th>
				<td><input name="bw" id="bw" type="text" value="10240"/></td>
			</tr>
			<tr>
				<th>Bandwidth Cycle</th>
				<td>
					<select name="bwp" id="bwp">
						<option value="m">Monthly</option>
						<option value="w">Weekly</option>
						<option value="d">Daily</option>
					</select>
				</td>
			</tr>
			<!--
			<tr>
				<th>Avoid NSFW Images?</th>
				<td>
					<select name="nsfw">
						<option value="2">Only unflagged images</option>
						<option value="1">Sketchy is okay</option>
						<option value="0">Anything goes</option>
					</select>
				</td>
			</tr>
			-->
			<tr class="req_openssl">
				<th>Auto-Update?</th>
				<td>
					<select name="update" id="update">
						<option value="1" class="req_openssl">Yes</option>
						<option value="0">No</option>
					</select>
				</td>
			</tr>
			<!--
			<tr class="req_openssl">
				<th>Auto-Verify?<sup><a href="http://suigintou.desudesudesu.org/meimei/terms#remote_execution">*</a></sup></th>
				<td>
					<select name="verify">
						<option value="1" class="req_openssl">Yes</option>
						<option value="0">No</option>
					</select>
				</td>
			</tr>
			-->
			<tr>
				<th colspan="2"><hr/></th>
			</tr>
			<tr>
				<th>Will you wind?</th>
				<td>
					<input type="submit" id="wind" value="Yes, I will - Install Meimei"/>
				</td>
			</tr>
		</table>
	</div>
	<div id="install" style="display: none">
		<img src="<?php echo $suigintou_laugh; ?>" style="border: 0px"/><br/>
		<b>Installing... </b>
	</div>
</td></tr></table>

<script type="text/javascript"><!--
	var fulluri = '<?php echo sanitize_js($fulluri); ?>';
	var server_name = '<?php echo sanitize_js($server_name); ?>';

	function run_tests(tests, work) {
		if (tests.length == 0) {
			$('#tests').append('<b>Tests complete</b><br/>');
			display_configure_ui(work);
			return;
		}

		var test = tests.shift();
		var dependencies = tests.shift();

		for (var i in dependencies) {
			var dep = dependencies[i];
			if (dep.substring(0, 1) == '!') {
				dep = dep.substring(1);
				if (work[dep] && work[dep]['success'] == 1) {
					$('#tests').append('<i>Skipping ' + test + ' (' + dep + '=1)</i><br/>');
					return run_tests(tests, work);
				}
			}
			else {
				if (!work[dep] || work[dep]['success'] == 0) {
					$('#tests').append('<i>Skipping ' + test + ' (' + dep + '=0)</i><br/>');
					return run_tests(tests, work);
				}
			}
		}

		$('#tests').append('[' + test + '] ');

		$.getJSON(fulluri + '?test_' + test, function(data) {
			work[test] = data;

			$('#tests').append(data['desc']);
			$('#tests').append(data['msg']);

			run_tests(tests, work);
		});
	}

	function test_passed(tests, test) {
		return tests[test] && tests[test]['success'];
	}

	function display_configure_ui(tests) {
		tests['openssl'] = true;
		if (test_passed(tests, 'openssl_extension_works'))
			tests['openssl_mode'] = 'extension';
		else if (test_passed(tests, 'openssl_binary_mode'))
			tests['openssl_mode'] = 'binary';
		else
			tests['openssl'] = false;

		var req_tests = [
			/* ['dns_valid', 'hostname is unresolvable'], */
			['download_rate', 'cannot fetch data from Suigintou'],
			['upload_rate', 'Suigintou cannot fetch data from this host']
		];

		for (var i in req_tests) {
			if (!test_passed(tests, req_tests[i][0])) {
				$('#config').empty().append('<b><font color="red">Unable to continue -- ' + req_tests[i][1] + '</font></b>').show('slow');
				return;
			}
		}
		
		$('#tests').hide('slow');
		$('#config').show('slow');

		$('#uri').val(fulluri);
		$('#d_uri').append(fulluri);

		var basedir = '<?php echo sanitize_js(dirname(__FILE__) . '/'); ?>';
		$('#basedir').val(basedir);
		$('#d_basedir').append(basedir);

		if (!test_passed(tests, 'dir_writable')) {
			$('#not_writable').append('<br/><small><b>Please create this directory and make it writable by the web server.</b></small>');
		}

		if (!tests['openssl'])
			$('.req_openssl').remove();

		$('#wind').click(function(){
			do_install(tests);
		});
	}

	function do_install(tests) {
		$('#config').hide('slow');
		$('#install').show('slow');

		var data = {
			'basedir' : $('#basedir').val(),
			'cache' : $('#cache').val(),
			'email' : $('#email').val(),
			'bwp' : $('#bwp').val(),
			'bw' : $('#bw').val(),
			'disk' : $('#disk').val(),
			'update' : $('#update').val(),
			'openssl_mode' : tests['openssl_mode']
		}

		var uri = $('#uri').val() + '?install';

		$.post(uri, data, function(data){
			if (data['success']) {
				$('#install').append('<font color="green">Ok!</font><br/><b>Registering install with Suigintou... </b>');
				do_register();
			}
			else {
				$('#install').append('<font color="red">Error!</font><br/>' + data['error']);
			}
		}, 'json');
	}

	function do_register() {
		var data = {
			'a' : 'register',
			'uri' : fulluri, 
			'email' : $('#email').val(),
			'disk' : $('#disk').val(),
			'bw' : $('#bw').val(),
			'bwp' : $('#bwp').val(),
			'update' : $('#update').val()
		}

		$.getJSON('http://suigintou.desudesudesu.org/meimei/api?callback=?', data, function(data) {
			if (data['success']) {
				$('#install').append('<font color="green">Ok!</font><br/>Meimei installed successfully!');
			}
			else {
				$('#install').append('<font color="red">Error!</font><br/>Unable to register install: ' + data['error'] + '<br/><b>Installation failed</b> :(');
			}
		});
	}

	$(document).ready(function(){
		$(document).ajaxError(function(asd,xhr) {
			alert(xhr.responseText);
		});

		run_tests([
			'php_version', [],
			'openssl_extension_installed', [],
			'openssl_extension_works', ['openssl_extension_installed'],
			'openssl_binary_installed', ['!openssl_extension_works'],
			'openssl_binary_works', ['openssl_binary_installed'],
			'dns_capability', [],
			'dns_resolves', ['dns_capability'],
			'dns_valid', ['dns_resolves'],
			'safe_mode', [],
			'allow_url_fopen', [],
			'dir_writable', [],
			'download_rate', ['allow_url_fopen', 'dns_capability'],
			'upload_rate', ['allow_url_fopen', 'dns_capability']
		], {});
	});
--></script>

</body>
</html>
