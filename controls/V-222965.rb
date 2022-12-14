control 'V-222965' do
  title 'LDAP authentication must be secured.'
  desc '
  JNDIRealm is an implementation of the Tomcat Realm interface. Tomcat uses
    the JNDIRealm to look up users in an LDAP directory server.  The realm\'s
    connection to the directory is defined by the \'connectionURL\' configuration
    attribute. This attribute is usually an LDAP URL that specifies the domain
    name of the directory server to connect to.

  The LDAP URL does not provide encryption by default. This can lead to
    authentication credentials being transmitted across network connections in
    clear text.

  To address this risk, Tomcat must be configured to use secure LDAP (LDAPS).
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server as a privileged user, run the following commands:

  sudo grep -i -A8 JNDIRealm $CATALINA_BASE/conf/server.xml

  If the JNDIRealm connectionURL setting is not configured to use LDAPS, if
    it does not exist, or is commented out, this is a finding.

  EXAMPLE:
  This is an example. Substitute localhost for the LDAP server IP and
    configure other LDAP-related settings as well.

  <Realm   className="org.apache.catalina.realm.JNDIRealm"
  connectionURL="ldaps://localhost:686"
  ...
  />
  '
  desc 'fix', '
  Identify the server IP that is providing LDAP services and configure the
    Tomcat user roles schema within LDAP. Refer to the manager and host-manager
    web.xml files for application specific role information that can be used
    for setting up the roles for those applications. The default location for
    these files is: $CATALINA_BASE/webapps/<AppName>/WEB-INF/web.xml

  From the Tomcat server console as a privileged user, edit the
    $CATALINA_BASE/conf/server.xml file.

  Locate the <Realm> element in the server.xml file, add a nested <Realm>
    element using the JNDIRealm className and configure the associated LDAP
    settings as per the LDAP server connection requirements.

  EXAMPLE:
  This is for illustration purposes only. The user must modify the LDAP
    settings on a case by case basis as per your individual LDAP server and
    schema.

  <Realm   className="org.apache.catalina.realm.JNDIRealm"
       connectionURL="ldaps://localhost:686"
         userPattern="uid={0},ou=people,dc=myunit,dc=mil"
            roleBase="ou=groups,dc=myunit,dc=mil"
            roleName="cn"
          roleSearch="(uniqueMember={0})"
  />
  '

  impact 0.5
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag gid: 'V-222965'
  tag rid: 'SV-222965r615938_rule'
  tag stig_id: 'TCAT-AS-000690'
  tag fix_id: 'F-24626r426340_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  realms = tomcat_server_file['//Realm/@className']

  describe 'LDAP authentication must be performed on the server. Check the Realm element for JNDIRealm configuration.' do
    subject { realms }
    it { should include 'org.apache.catalina.realm.JNDIRealm' }
  end

  compliant_connection_url = tomcat_server_file['//Realm[@className=\'org.apache.catalina.realm.JNDIRealm\']/@connectionURL'].collect { |x| x.match('ldaps') }

  describe 'The connectionURL element of the JDNDIRealm must use ldaps for encyption' do
    subject { compliant_connection_url }
    it { should include 'ldaps' }
  end
end
