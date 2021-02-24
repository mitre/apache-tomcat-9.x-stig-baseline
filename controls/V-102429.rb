control 'V-102429' do
  title "Secured connectors must be configured to use strong encryption ciphers.\n"
  desc  "The Tomcat $Connector element controls the TLS protocol and the
associated ciphers used. If a strong cipher is not selected, an attacker may be
able to circumvent encryption protections that are configured for the
connector. Strong ciphers must be employed when configuring a secured connector.

    The configuration attribute and its values depend on what HTTPS
implementation the user is utilizing. The user may be utilizing either
Java-based implementation aka JSSE — with BIO and NIO connectors, or
OpenSSL-based implementation — with APR connector.

    TLSv1.2 ciphers are configured via the server.xml file on a per connector
basis.  For a list of approved ciphers, refer to NIST SP 800-52 section 3.3.1.1.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command:

    sudo grep -i ciphers $CATALINA_BASE/conf/server.xml.

    Examine each <Connector/> element that is not a redirect to a secure port.
Identify the ciphers that are configured on each connector and determine if any
of the ciphers are not secure.

    For a list of approved ciphers, refer to NIST SP 800-52 section 3.3.1.1.

    If insecure ciphers are configured for use, this is a finding.
  "
  desc 'fix', "
    As a privileged user on the Tomcat server, edit the
$CATALINA_BASE/conf/server.xml and modify the <Connector/> element.

    Add the SSLEnabledProtocols=\"TLSv1.2\" setting to the connector or modify
the existing setting.

    Set SSLEnabledProtocols=\"TLSv1.2\". Save the server.xml file and restart
Tomcat:
    sudo systemctl restart tomcat
    sudo systemctl reload-daemon
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag gid: 'V-102429'
  tag rid: 'SV-111373r1_rule'
  tag stig_id: 'TCAT-AS-000020'
  tag fix_id: 'F-107971r5_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  ssp_ssl_enabled_protocols = input('ssl_enabled_protocols')
  connector_count = tomcat_server_file['//Connector'].count

  (1..connector_count).each do |i|
    describe tomcat_server_file do
      its(["//Connector[#{i}]/@SSLEnabledProtocols"]) { should cmp ssp_ssl_enabled_protocols }
    end
  end

  if tomcat_server_file['//Connector'].empty?
    impact 0.0
    describe "No Connector elements were found in #{tomcat_server_file}" do
      skip 'Test Skipped'
    end
  end
end
