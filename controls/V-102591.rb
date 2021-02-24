control 'V-102591' do
  title 'ALLOW_BACKSLASH must be set to false.'
  desc  "When Tomcat is installed behind a proxy configured to only allow
access to certain Tomcat contexts (web applications), an HTTP request
containing \"/\\../\" may allow attackers to work around the proxy restrictions
using directory traversal attack methods. If allow_backslash is true the '\\'
character will be permitted as a path delimiter. The default value for the
setting is false but Tomcat should always be configured as if no proxy
restricting context access was used and allow_backslash should be set to false
to prevent directory traversal style attacks. This setting can create
operability issues with non-compliant clients. In order to accommodate a
non-compliant client, any deviation from the STIG setting must be approved by
the ISSO."
  desc  'rationale', ''
  desc  'check', "
    If the ISSO has accepted the risk for enabling the ALLOW_BACKSLASH setting,
this requirement is NA.

    From the Tomcat server as an elevated user, run the following command:

    sudo grep -i ALLOW_BACKSLASH $CATALINA_BASE/conf/catalina.properties

    sudo grep -i catalina_opts /etc/systemd/system/tomcat.service

    If org.apache.catalina.connector. ALLOW_BACKSLASH=true, this is a finding.
  "
  desc 'fix', "
    As a privileged user on the Tomcat server:

    If the finding is in the catalina.properties file, edit the
$CATALINA_BASE/conf/catalina.properties file.

    sudo nano $CATALINA_BASE/conf/catalina.properties

    Change the org.apache.catalina.connector.ALLOW_BACKSLASH=true setting to
=false.

    If the finding is in the /etc/systemd/services/tomcat/service file, edit
the file using a text editor.

    sudo nano /etc/systemd/services/tomcat.service

    Locate the \"Environment='CATALINA_OPTS=' line and change the
-D.org.apache.catalina.connectorALLOW_BACKSLASH=true setting to =false.

    Restart Tomcat by running the following commands:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-102591'
  tag rid: 'SV-111531r1_rule'
  tag stig_id: 'TCAT-AS-001680'
  tag fix_id: 'F-108123r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  catalina_base = input('catalina_base')
  describe 'The systemd startup file must exist' do
    subject { service('tomcat') }
    it { should be_installed }
  end

  unless service('tomcat').params.empty?
    describe service('tomcat').params['Environment'] do
      it { should_not match '-D.org.apache.catalina.connector.ALLOW_BACKSLASH=true' }
    end
  end

  describe "#{catalina_base}/conf/catalina.properties config" do
    subject { parse_config_file("#{catalina_base}/conf/catalina.properties").params }
    its(['org.apache.catalina.connector.ALLOW_BACKSLASH']) { should_not cmp 'true' }
  end
end
