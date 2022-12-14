control 'V-222935' do
  title 'Connectors must be secured.'
  desc '
  The unencrypted HTTP protocol does not protect data from interception or
    alteration which can subject users to eavesdropping, tracking, and the
    modification of received data. To secure an HTTP connector, both the secure
    and scheme flags must be set.
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server console, run the following command:

  sudo cat $CATALINA_BASE/conf/server.xml.

  Examine each <Connector/> element.

  For each connector, verify the secure= flag is set to "true" and the
    scheme= flag is set to "https" on each connector.

  If the secure flag is not set to "true" and/or the scheme flag is not set
    to "https" for each HTTP connector element, this is a finding.
  '
  desc 'fix', '
  From the Tomcat server as a privileged user, edit the server.xml file.

  sudo nano $CATALINA_BASE/conf/server.xml.

  Locate each <Connector/> element which is lacking a secure setting.

  EXAMPLE Connector:
  <Connector port="8080" protocol="HTTP/1.1"
                 connectionTimeout="20000"
                 redirectPort="443" />

  Set or add scheme="https" and secure="true" for each HTTP connector
    element.

  EXAMPLE:
  <Connector port="443"
    protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true"
      maxThreads="150" scheme="https" secure="true".../>

  Save the server.xml file and restart Tomcat:
  sudo systemctl restart tomcat
  sudo systemctl reload-daemon
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-0000241'
  tag gid: 'V-222935'
  tag rid: 'SV-222935r615938_rule'
  tag stig_id: 'TCAT-AS-000100'
  tag fix_id: 'F-24596r426250_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  if tomcat_server_file['//Connector'].empty?
    impact 0.0
    describe "No Connector elements were found in #{tomcat_server_file}" do
      skip 'Test Skipped'
    end
  else
    connectors_count = tomcat_server_file['//Connector/'].count
    (1..connectors_count).each do |_i|
      describe tomcat_server_file do
        its(['//Connector/@secure']) { should include true }
        its(['//Connector/@scheme']) { should include 'https' }
      end
    end
  end
end
