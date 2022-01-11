<?php
/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; under version 2
 * of the License (non-upgradable).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2014 (original work) Open Assessment Technologies SA;
 *
 *
 */

/**
 * Authentication user for key value db access
 *
 * @author christophe massin
 * @package authLdap

 */


namespace oat\authLdap\model;

use oat\oatbox\Configurable;
use oat\taoTestTaker\models\CrudService;
use oat\generis\model\user\UserRdf;
use oat\tao\model\TaoOntology;
use oat\oatbox\service\ServiceManager;
use oat\generis\Helper\UserHashForEncryption;


class LdapUserFactory extends Configurable {

    const OPTION_USERFACTORY = 'user_factory';
    public function createUser($rawData) {

        if (!isset($rawData['dn'])) {
            throw new \common_exception_InconsistentData('Missing DN for LDAP user');
        } else {
            $id = $rawData['dn'];
        }

        $data = array();
        $userdata = array();


        foreach ($this->getRules() as $property => $rule) {
            $data[$property] = $this->map($rule, $rawData);
            $userdata[$property] = $data[$property][0];
        }


        $taouser = null;

        // check if login already exists - Create if not, and add the delivery role!

        if (! \core_kernel_users_Service::loginExists($userdata[PROPERTY_USER_LOGIN])) {
           $crudservice = CrudService::singleton();
           $taouser = $crudservice->CreateFromArray( $userdata );
        } 
		
	    // Retrieve the specified user.
	    $userResource = \core_kernel_users_Service::getOneUser( $userdata[PROPERTY_USER_LOGIN] );		
		// \common_Logger::i("LdapUserFactory authenticate taouser".print_r($userResource, true));
		
		$userFactory = ServiceManager::getServiceManager()->get('generis/userFactory') ;
		if ($userFactory instanceof UserFactoryServiceInterface) {
			
			\common_Logger::i("UserFactoryService createUser ");
			return $userFactory->createUser($userResource, UserHashForEncryption::hash($this->password));
		}	 
		
		return $userFactory->createUser($userResource, UserHashForEncryption::hash($this->password));

       
        return new LdapUser($taouser->getUri(), $data);
    }

    public function map($propertyConfig, $rawData) {
        $data = array();
        switch ($propertyConfig['type']) {
            case 'value' :
                $data = $propertyConfig['value'];
                break;
            case 'attributeValue' :
                if (isset($rawData[$propertyConfig['attribute']])) {
                    $value = $rawData[$propertyConfig['attribute']];
                    $data = is_array($value) ? $value : array($value);
                }
                break;
//            case 'conditionalvalue' :
//                if (isset($rawData[$propertyConfig['attribute']]) &&
//                    isset($rawData[$propertyConfig['attributematch']) ) {
//                    // iterate raw data looking for attribute = attribute match
//                    // set data = value property if determined to be true.
//                }
//                break;
            case 'callback' :
                if (isset($rawData[$propertyConfig['attribute']])) {
                    $callback = $propertyConfig['callable'];
                    if (is_callable($callback)) {
                        $data = call_user_func($callback, $rawData[$propertyConfig['attribute']]);
                    }
                }
                break;
            default :
                throw new \common_exception_InconsistentData('Unknown mapping: '.$propertyConfig['type']);
        }
        return $data;
    }

    public function getRules() {
        $rules = self::getDefaultConfig();
        foreach ($this->getOptions() as $key => $value) {
            $rules[$key] = $value;
        }
        return $rules;
    }

    static public function getDefaultConfig()
    {
        return array(
            PROPERTY_USER_ROLES         => self::rawValue(TaoOntology::PROPERTY_INSTANCE_ROLE_DELIVERY)
            ,PROPERTY_USER_UILG         => self::rawValue(DEFAULT_LANG)
            ,PROPERTY_USER_DEFLG        => self::rawValue(DEFAULT_LANG)
            ,PROPERTY_USER_TIMEZONE     => self::rawValue(TIME_ZONE)
            ,PROPERTY_USER_MAIL         => self::attributeValue('mail')
            ,PROPERTY_USER_FIRSTNAME    => self::attributeValue('givenname')
            ,PROPERTY_USER_LASTNAME     => self::attributeValue('sn')
            ,PROPERTY_USER_LOGIN        => self::attributeValue('samaccountname')
            ,PROPERTY_USER_PASSWORD     => self::rawValue('RANDOM_ABZGD'.rand())
            ,RDFS_LABEL                 => self::attributeValue('mail')
        );
    }

    static protected function rawValue($value) {
        return array(
            'type' => 'value',
            'value' => array($value)
        );
    }

    static protected function attributeValue($attributeName) {
        return array(
            'type' => 'attributeValue',
            'attribute' => $attributeName
        );
    }

    static protected function callback($callable, $attributeName) {
        return array(
            'type' => 'callback',
            'callable' => $callable,
            'attribute' => $attributeName
        );
    }
}
