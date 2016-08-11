<?php

class QAuth_Core32 extends QAuth_Abstract
{
	/**
	 *   Password info for this authentication object
         */
	protected $_data = array();
        
        protected $passwordIterations = '10';

	/**
	 *   Initialize data for the authentication object.
	 */
	public function setData($data)
	{
		$this->_data = unserialize($data);
	}

	/**
	 *   Generate new authentication data
	 *   @see QAuth_Abstract::generate()
	 */
	public function generate($password)
	{
		$passwordHash = new QAuth_PasswordHash($passwordIterations, false);
		$output = array('hash' => $passwordHash->HashPassword($password));
		return serialize($output);
	}

	/**
	 *   Authenticate against the given password
	 *   @see QAuth_Abstract::authenticate()
	 */
	public function authenticate($userId, $password)
	{
		if (!is_string($password) || $password === '' || empty($this->_data))
		{
			return false;
		}

		$passwordHash = new QAuth_PasswordHash($passwordIterations, false);
		return $passwordHash->CheckPassword($password, $this->_data['hash']);
	}
}
