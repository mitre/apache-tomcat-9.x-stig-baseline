control 'V-102433' do
  title "TLS 1.2 must be used on secured HTTP connectors.\n"
  desc  "Using older versions of TLS introduces security vulnerabilities that
exist in the older versions of the protocol. Tomcat by default will use all
available versions of the SSL/TLS protocols unless the version is explicitly
defined in the SSL configuration attribute for the associated connector. This
introduces the opportunity for the client to negotiate the use of an older
protocol version and increases the risk of compromise of the Tomcat server.

    All connectors must use TLS 1.2. While this check specifically verifies the
use of TLSv1.2, it does not provide all of the steps required to successfully
configure a secured TLS connection. That task involves multiple additional
steps that are not included here. Refer to Tomcat documentation for all of the
steps needed to create a TLS protected connector.


  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command:

    sudo cat $CATALINA_BASE/conf/server.xml.

    Examine each <Connector/> element.

    For every HTTP protocol connector:
    Verify the SSLEnabledProtocols=\"TLSv1.2\" flag is set on each connector.

    If the SSLEnabledProtocols setting is not set to TLSv1.2 or greater, this
is a finding.
  "
  desc 'fix', "
    As a privileged user on the Tomcat server, edit the
$CATALINA_BASE/conf/server.xml and modify the <Connector/> element.

    Add the \"SSLEnabledProtocols=\" flag to the connector or modify the
existing flag.

    Set SSLEnabledProtocols=\"TLSv1.2\". Save the server.xml file and restart
Tomcat:
    sudo systemctl restart tomcat
    sudo systemctl reload-daemon
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag satisfies: %w(SRG-APP-000015-AS-000010 SRG-APP-000172-AS-000120
SRG-APP-000439-AS-000155)
  tag gid: 'V-102433'
  tag rid: 'SV-111547r1_rule'
  tag stig_id: 'TCAT-AS-000040'
  tag fix_id: 'F-107975r4_fix'
  tag cci: %w(CCI-000197 CCI-001453 CCI-002418)
  tag nist: ['IA-5 (1) (c)', 'AC-17 (2)', 'SC-8']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  if tomcat_server_file['//Connector'].empty?
    impact 0.0
    describe "No Connector elements were found in #{tomcat_server_file}" do
      skip 'Test Skipped'
    end
  else
    ssp_ssl_enabled_protocols = input('ssl_enabled_protocols')
    connector_count = tomcat_server_file['//Connector'].count

    (1..connector_count).each do |i|
      describe tomcat_server_file do
        its(["//Connector[#{i}]/@SSLEnabledProtocols"]) { should cmp ssp_ssl_enabled_protocols }
      end
    end
  end
end
