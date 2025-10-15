control 'SV-222979' do
  title 'Idle timeout for the management application must be set to 10 minutes.'
  desc "Tomcat can set idle session timeouts on a per application basis. The management application is provided with the Tomcat installation and is used to manage the applications that are installed on the Tomcat Server. Setting the idle timeout for the management application will kill the admin user's session after 10 minutes of inactivity. This will limit the opportunity for unauthorized persons to hijack the admin session. This setting will also affect the default timeout behavior of all hosted web applications. To adjust the individual hosted application settings that are not related to management of the system, modify the individual application web.xml file if application timeout requirements differ from the STIG. 

"
  desc 'check', 'If the manager application has been deleted from the system, this is not a finding. 

From the Tomcat server as a privileged user, run the following commands:

sudo grep -i session-timeout $CATALINA_BASE/webapps/manager/META-INF/web.xml 

sudo grep -i session-timeout 
$CATALINA_BASE/conf/web.xml

If the session-timeout setting is not configured to be 10 minutes in at least one of these files, this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user:

To affect session timeout for all applications including the management application, edit the $CATALINA_BASE/conf/web.xml file.

To affect session timeout for the management application only, edit the $CATALINA_BASE/webapps/manager/META-INF/web.xml file. 

Locate the session-timeout setting located within the session-config element.

Modify the session-timeout setting to be 10 minutes.

Save the file.

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  tag check_id: 'C-24651r426381_chk'
  tag severity: 'medium'
  tag gid: 'V-222979'
  tag rid: 'SV-222979r1043182_rule'
  tag stig_id: 'TCAT-AS-000970'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-24640r985896_fix'
  tag satisfies: ['SRG-APP-000389', 'SRG-APP-000220']
  tag 'documentable'
  tag legacy: ['SV-111481', 'V-102541']
  tag cci: ['CCI-004895', 'CCI-002361', 'CCI-002038']
  tag nist: ['SC-11 b', 'AC-12', 'IA-11']

  unless input('manager_app_installed')
    impact 0.0
    desc 'caveat', 'The manager application is not installed. This is not a finding'
  end

  catalina_base = input('catalina_base')
  tomcat_web_xmls = %W(#{catalina_base}/conf/web.xml #{catalina_base}/webapps/manager/META-INF/web.xml)
  session_timeouts = []

  tomcat_web_xmls.each do |web_xml|
    if file("#{web_xml}").exist?
      session_timeouts.concat(xml("#{web_xml}")['//session-timeout'])
    end
  end

  describe 'The session-timeout setting must be set to 10 minutes in either the manager application or overall web.xml file' do
    subject { session_timeouts }
    it { should include 10 }
  end
end
