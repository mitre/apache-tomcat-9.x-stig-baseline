control 'SV-222962' do
  title 'Tomcat management applications must use LDAP realm authentication.'
  desc 'Using the local user store on a Tomcat installation does not meet a multitude of security control requirements related to user account management. To address this risk, Tomcat must be configured to utilize an LDAP or Active Directory installation that provides a centralized user account store that is configured to meet standard DoD user account management requirements. JNDIRealm is an implementation of the Tomcat Realm interface that looks up users in an LDAP directory server accessed by a JNDI provider (typically, the standard LDAP provider that is available with the JNDI API classes). The realm supports a variety of approaches to using a directory for authentication.'
  desc 'check', 'If manager and host-manager applications have been deleted from the system, this is not a finding. 

From the Tomcat server as a privileged user, run the following commands:

sudo grep -i -A8 JNDIRealm $CATALINA_BASE/conf/server.xml

If the JNDIRealm does not exist or if the JNDIRealm configuration is commented out, this is finding.'
  desc 'fix', 'Identify the server IP that is providing LDAP services and configure the Tomcat user roles schema within LDAP. Refer to the manager and host-manager web.xml files for application specific role information that can be used for setting up the roles for those applications. The default location for these files is: $CATALINA_BASE/webapps/<AppName>/WEB-INF/web.xml

From the Tomcat server console as a privileged user, edit the $CATALINA_BASE/conf/server.xml file.

Locate the <Realm> element in the server.xml file, add a nested <Realm> element using the JNDIRealm className and configure the associated LDAP settings as per the LDAP server connection requirements.

EXAMPLE:
This is for illustration purposes only. Modify the LDAP settings on a case-by-case basis as per the individual LDAP server and schema.

<Realm   className="org.apache.catalina.realm.JNDIRealm"
     connectionURL="ldaps://localhost:686"
       userPattern="uid={0},ou=people,dc=myunit,dc=mil"
          roleBase="ou=groups,dc=myunit,dc=mil"
          roleName="cn"
        roleSearch="(uniqueMember={0})"
/>'
  impact 0.5
  tag check_id: 'C-24634r426330_chk'
  tag severity: 'medium'
  tag gid: 'V-222962'
  tag rid: 'SV-222962r1051118_rule'
  tag stig_id: 'TCAT-AS-000600'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-24623r426331_fix'
  tag 'documentable'
  tag legacy: ['SV-111449', 'V-102507']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  if !input('manager_app_installed') && !input('host_manager_app_installed')
    impact 0.0
    desc 'caveat', 'Manager and host-manager applications have been deleted from the system, this is not a finding.'

    describe 'Manager and host-manager applications are not installed.' do
      skip 'Manager and host-manager applications are not installed. Skipping this check'
    end
  else
    catalina_base = input('catalina_base')
    tomcat_server_file_location = "#{catalina_base}/conf/server.xml"
    if file(tomcat_server_file_location).exist?
      tomcat_server_file = xml(tomcat_server_file_location)
      realms = tomcat_server_file['//Realm/@className']

      describe 'LDAP authentication must be performed on the server. Check the Realm element for JNDIRealm configuration.' do
        subject { realms }
        it { should include 'org.apache.catalina.realm.JNDIRealm' }
      end
    else
      describe file(tomcat_server_file_location) do
        it { should exist }
      end
    end
  end
end
