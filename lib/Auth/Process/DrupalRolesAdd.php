<?php

   /**
    * Filter to add attributes.
    *
    * This filter allows you to add attributes to the attribute set being processed.
    *
    * @author Olav Morken, UNINETT AS.
    * @package simpleSAMLphp
    */

class sspmod_drupalRolesAdd_Auth_Process_DrupalRolesAdd extends SimpleSAML_Auth_ProcessingFilter {

  /**
   * Flag which indicates wheter this filter should append new values or replace old values.
   */
  private $replace = FALSE;


  /**
   * Attributes which should be added/appended.
   *
   * Assiciative array of arrays.
   */
  private $attributes = array();


  /**
   * The DSN we should connect to.
   */
  private $dsn;


  /**
   * The username we should connect to the database with.
   */
  private $username;


  /**
   * The password we should connect to the database with.
   */
  private $password;


  /**
   * The query we should use to retrieve the attributes for the user.
   *
   * The username and password will be available as :username and :password.
   */
  private $query;

  
  private $userAttribute;

  /**
   * Initialize this filter.
   *
   * @param array $config  Configuration information about this filter.
   * @param mixed $reserved  For future use.
   */
  public function __construct($config, $reserved) {
    parent::__construct($config, $reserved);

    assert('is_array($config)');

    foreach (array('dsn', 'username', 'password', 'attribute') as $param) {
      if (!array_key_exists($param, $config)) {
	throw new Exception('Missing required attribute \'' . $param .
			    '\' for authentication source ' . $this->authId);
      }
		  
      if (!is_string($config[$param])) {
	throw new Exception('Expected parameter \'' . $param .
			    '\' for authentication source ' . $this->authId .
			    ' to be a string. Instead it was: ' .
			    var_export($config[$param], TRUE));
      }
    }
		
    $this->dsn = $config['dsn'];
    $this->username = $config['username'];
    $this->password = $config['password'];
    //    $this->query = $config['query'];
    $this->userAttribute = $config['attribute']; 		
  }


  /**
   * Create a database connection.
   *
   * @return PDO  The database connection.
   */
  private function connect() {
    try {
      $db = new PDO($this->dsn, $this->username, $this->password);
    } catch (PDOException $e) {
      throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
			  $this->dsn . '\': '. $e->getMessage());
    }

    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


    $driver = explode(':', $this->dsn, 2);
    $driver = strtolower($driver[0]);

    /* Driver specific initialization. */
    switch ($driver) {
    case 'mysql':
      /* Use UTF-8. */
      $db->exec("SET NAMES 'utf8'");
      break;
    case 'pgsql':
      /* Use UTF-8. */
      $db->exec("SET NAMES 'UTF8'");
      break;
    }

    return $db;
  }


  private function getRolesForUser($userid) {
    assert('is_string($userid)');
	$db = $this->connect();

	$query = "SELECT role.name FROM public.role 
        LEFT JOIN public.users_roles USING (rid) LEFT JOIN public.authmap USING (uid) 
        WHERE authmap.authname = :userid ";

	try {
	  $sth = $db->prepare($query);
	} catch (PDOException $e) {
	  throw new Exception('drupalrolesadd:'. 
			      ': - Failed to prepare query: ' . $e->getMessage());
	}

	try {
	  $res = $sth->execute(array(':userid' => (string)$userid[0]));
	} catch (PDOException $e) {
	  throw new Exception('drupalrolesadd:'.
			      ': - Failed to execute query: ' . $e->getMessage());
	}
	
	try {
	  $data = $sth->fetchAll();
	} catch (PDOException $e) {
	  throw new Exception('drupalrolesadd:'.
			      ': - Failed to fetch result set: ' . $e->getMessage());
	}

	error_log('drupalrolesadd:'. ': Got ' . count($data) .
				' rows from database');
	
	if (count($data) === 0) {
	  /* No rows returned - no roles, but this is not an error condition */
	  error_log('drupalrolesadd:'.
				   ': No rows in result set. Probably, user "'.$userid[0].'" has no assigned role in Drupal.');
	 
	}
	$roles = array();
	foreach ($data as $value) {
	  if ($value === NULL) {
	    continue;
	  }
	  
	  array_push ($roles, (string)$value[0]);
	}
	return $roles;
    
  }



  /**
   * Apply filter to add or replace attributes.
   *
   * Add or replace existing attributes with the configured values.
   *
   * @param array &$request  The current request
   */
  public function process(&$request) {
    assert('is_array($request)');
    assert('array_key_exists("Attributes", $request)');

    $attributes =& $request['Attributes'];
   
    if (!array_key_exists($this->userAttribute, $attributes)) {
          throw new Exception('Missing required attribute ' . $this->userAttribute);
    }


    $userid = $attributes[$this->userAttribute];

    $values = $this->getRolesForUser($userid);
    
    if(!is_array($values)) {
      $values = array($values);
    }
    foreach($values as $value) {
      if(!is_string($value)) {
	throw new Exception('Invalid value for attribute ' . $name . ': ' .
			    var_export($values, TRUE));
      }
    }
    if (count ($values) > 0) {
      $this->attributes['roles'] = $values;
    }


   

    foreach($this->attributes as $name => $values) {
      if($this->replace === TRUE || !array_key_exists($name, $attributes)) {
	$attributes[$name] = $values;
      } else {
	$attributes[$name] = array_merge($attributes[$name], $values);
      }
    }
  }
  
  }

?>
