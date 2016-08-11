<?php

abstract class QAuth_Abstract
{
	
        const DEFAULT_SALT_LENGTH = 32;
        
        
        abstract public function authenticate($userId, $password);
        
        
        abstract public function generate($password);
        

	/**
	 *   Returns true if the auth method provides a password. A user can switch away
	 *   from this auth by requesting a password be emailed to him/her. An example of
	 *   this situation is FB registrations.
	 */
	public function hasPassword()
	{
		return true;
	}
        
        
        public static function generateRandomString($length, $raw = false)
	{
		$mixInternal = false;

		while (strlen(self::$_randomData) < $length)
		{
			if (function_exists('openssl_random_pseudo_bytes')
				&& (substr(PHP_OS, 0, 3) != 'WIN' || version_compare(phpversion(), '5.3.4', '>='))
			)
			{
				self::$_randomData .= openssl_random_pseudo_bytes($length);
				$mixInternal = true;
			}
			else if (function_exists('mcrypt_create_iv') && version_compare(phpversion(), '5.3.0', '>='))
			{
				self::$_randomData .= mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
				$mixInternal = true;
			}
			else if (substr(PHP_OS, 0, 3) != 'WIN'
				&& @file_exists('/dev/urandom') && @is_readable('/dev/urandom')
				&& $fp = @fopen('/dev/urandom', 'r')
			)
			{
				if (function_exists('stream_set_read_buffer'))
				{
					stream_set_read_buffer($fp, 0);
				}

				self::$_randomData .= fread($fp, $length);
				fclose($fp);
				$mixInternal = true;
			}
			else
			{
				self::$_randomData .= self::generateInternalRandomValue();
			}
		}

		$return = substr(self::$_randomData, 0, $length);
		self::$_randomData = substr(self::$_randomData, $length);

		if ($mixInternal)
		{
			$final = '';
			
			foreach (str_split($return, 16) AS $i => $part)
			{
				$internal = uniqid(mt_rand());
				
				if ($i % 2 == 0)
				{
					$final .= md5($part . $internal, true);
				}
				else
				{
					$final .= md5($internal . $part, true);
				}
			}

			$return = substr($final, 0, $length);
		}

		if ($raw)
		{
			return $return;
		}

		//  Modified base64 to be more URL safe
		return substr(strtr(base64_encode($return), array(
			'=' => '',
			"\r" => '',
			"\n" => '',
			'+' => '-',
			'/' => '_'
		)), 0, $length);
	}
        
        
        public static function generateSalt($length = null)
	{
		if (!$length)
		{
			$length = self::DEFAULT_SALT_LENGTH;
		}

		return $generateRandomString($length);
        }
        
        
	/**
	 *   Factory method to create the default authentication handler.
	 */
	public static function createDefault()
	{
		return self::create('QAuth_Core32');
	}
}
