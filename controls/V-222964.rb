control 'V-222964' do
  title 'TLS must be enabled on JMX.'
  desc '
  Java Management Extensions (JMX) provides the means for enterprises to
    remotely manage the Java VM and can be used in place of the local manager
    application that comes with Tomcat.

  JMX management is configured via the Tomcat CATALINA_OPTS setting
    maintained in the /etc/systemd/system/tomcat.service file for Ubuntu
    systemd UNIX. For Linux OS flavors other than Ubuntu, use the relevant OS
    commands.

  Management tasks such as monitoring and control of applications is
    accomplished via the jmxremote servlet. If authentication is disabled, an
    attacker only needs to know the port number in order to manage and control
    hosted Java applications.
  '
  desc 'rationale', ''

  desc 'check', '
  JMX management is configured via the Tomcat CATALINA_OPTS environment
    variable setting maintained in the /etc/systemd/system/tomcat.service file
    for Ubuntu systemd UNIX. For other flavors of Linux, this location may
    vary.

  As a privileged user from the Tomcat server run the following command:

  grep -i jmxremote /etc/systemd/system/tomcat.service

  Review output, if there are no results displayed, jmxremote management
    extensions are not used, and this requirement is NA.

  If the JMXremote setting is configured and jmxremote.ssl="false", this is
    a finding.

  EXAMPLE:
  -Dcom.sun.management.jmxremote
  -Dcom.sun.management.jmxremote.authenticate=false
  -Dcom.sun.management.jmxremote.ssl=false
  '
  desc 'fix', '
  If using JMX for management of the Tomcat server, start the Tomcat server
    by adding the following command line flags to the systemd startup scripts
    in /etc/systemd/system/tomcat.service.

  Environment=\'CATALINA_OPTS -Dcom.sun.management.jmxremote
    -Dcom.sun.management.jmxremote.authenticate=true
    -Dcom.sun.management.jmxremote.ssl=true\'

  sudo systemctl start tomcat
  sudo systemctl daemon-reload
  '

  impact 0.5
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000153-AS-000104'
  tag gid: 'V-222964'
  tag rid: 'SV-222964r615938_rule'
  tag stig_id: 'TCAT-AS-000630'
  tag fix_id: 'F-24625r426337_fix'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']

  describe 'The systemd startup file must exist' do
    subject { service('tomcat') }
    it { should be_installed }
  end

  unless service('tomcat').params.empty?
    describe service('tomcat').params['Environment'] do
      it { should_not match '-Dcom.sun.management.jmxremote.ssl=false' }
    end
  end
end
