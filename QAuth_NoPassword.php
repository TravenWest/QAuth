<?php

/**
 *   No password authentication method. This is used, for example, when connecting with FB
 *   and no password is set.
 */
class QAuth_NoPassword extends QAuth_Abstract
{
        
	/**
	 *   Initialize data for the authentication object.
	 */
	public function setData($data)
	{
	}
        
        
	/**
	 *   Generate new authentication data
	 *   @see QAuth_Abstract::generate()
	 */
	public function generate($password)
	{
		return serialize(array());
	}
        
        
	/**
	 *   Authenticate against the given password
	 *   @see QAuth_Abstract::authenticate()
	 */
	public function authenticate($userId, $password)
	{
		return false;
	}
        
        
	/**
	 *   Determines if auth method provides password.
	 *   @see QAuth_Abstract::hasPassword()
	 */
	public function hasPassword()
	{
		return false;
	}
}
