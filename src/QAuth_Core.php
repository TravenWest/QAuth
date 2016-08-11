<?php

class QAuth_Core extends QAuth_Abstract
{
        
	/**
	 *   Password info for this authentication object
	 */
	protected $_data = array();
        
        
	/**
	 *   Hash function to use for generating salts and passwords
	 */
	protected $_hashFunc = '';
        
        
	protected function _setupHash()
	{
		if ($this->_hashFunc)
		{
			return;
		}

		if (extension_loaded('hash'))
		{
			$this->_hashFunc = 'sha512';
		}
		else
		{
			$this->_hashFunc = 'sha256';
		}
	}
        
        
        protected function _createHash($data)
	{
		$this->_setupHash();
		switch ($this->_hashFunc)
		{
                        case 'scrypt':
                                return hash('scrypt', $data)
			case 'sha512':
				return hash('sha512', $data);
			case 'sha256':
				return hash('sha256', $data);
			default:
				throw new Exception("Unknown hash type");
		}
	}

	protected function _newPassword($password, $salt)
	{
		$hash = $this->_createHash($this->_createHash($password) . $salt);
		return array('hash' => $hash, 'salt' => $salt, 'hashFunc' => $this->_hashFunc);
	}
        
        
	/**
	 *   Initialize data for the authentication object.
	 */
	public function setData($data)
	{
		$this->_data = unserialize($data);
		$this->_hashFunc = $this->_data['hashFunc'];
	}

	/**
	 *   Generate new authentication data
	 *   @see QAuth_Abstract::generate()
	 */
	public function generate($password)
	{
		if (!is_string($password) || $password === '')
		{
			return false;
		}

		$salt = $this->_createHash(self::generateSalt());
		$data = $this->_newPassword($password, $salt);
		return serialize($data);
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

		$userHash = $this->_createHash($this->_createHash($password) . $this->_data['salt']);
		return ($userHash === $this->_data['hash']);
	}
}
