control 'V-102569' do
  title "Multifactor certificate-based tokens (CAC) must be used when accessing
the management interface."
  desc  "Password authentication does not provide sufficient security control
when accessing a management interface. DoD has specified that the CAC will be
used when authenticating and passwords will only be used when CAC
authentication is not a plausible solution. Tomcat provides the ability to do
certificate based authentication and client authentication; therefore, the
Tomcat server must be configured to use CAC."
  desc  'rationale', ''
  desc  'check', "
    If the manager application has been deleted from the Tomcat server, this is
not a finding. From the Tomcat server as a privileged user, issue the following
command:

    sudo grep -i auth-method $CATALINA_BASE/webapps/manager/WEB-INF/web.xml

    If the <Auth-Method> for the web manager application is not set to
CLIENT-CERT, this is a finding.
  "
  desc 'fix', "
    From the Tomcat server as a privileged user, edit the
$CATALINA_BASE/webapps/manager/WEB-INF/web.xml file and modify the auth-method
for the manager application security constraint.

    sudo nano $CATALINA_BASE/webapps/manager/WEB-INF/web.xml

    Locate <auth-method> contained within the <login-config> section, modify
<auth-method> to specify CLIENT-CERT.

    EXAMPLE:
    <auth-method>CLIENT-CERT</auth-method>

    In addition, the connector used for accessing the manager application must
be configured to require client authentication by setting clientAuth=\"true\"
and the manager application roles must be configured in the LDAP server.

    Restart the Tomcat server:
    sudo systemctl restart tomcat
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000391-AS-000239'
  tag satisfies: %w(SRG-APP-000391-AS-000239 SRG-APP-000392-AS-000240
SRG-APP-000402-AS-000247 SRG-APP-000403-AS-000248)
  tag gid: 'V-102569'
  tag rid: 'SV-111509r1_rule'
  tag stig_id: 'TCAT-AS-001320'
  tag fix_id: 'F-108101r1_fix'
  tag cci: %w(CCI-001953 CCI-001954 CCI-002009 CCI-002010)
  tag nist: ['IA-2 (12)', 'IA-2 (12)', 'IA-8 (1)', 'IA-8 (1)']

  if !input('manager_app_installed')
    impact 0.0
    desc 'caveat', 'The manager application is not installed. This is not a finding'

    describe 'The manager application is not installed.' do
      skip 'The manager application is not installed. This is not a finding'
    end
  else
    catalina_base = input('catalina_base')
    tomcat_manager_web_file = xml("#{catalina_base}/webapps/manager/WEB-INF/web.xml")

    describe "The authentication method for the 'auth-method' element must be set to 'CLIENT-CERT'" do
      subject { tomcat_manager_web_file['//auth-method'] }
      it { should cmp 'CLIENT-CERT' }
    end
  end
end
