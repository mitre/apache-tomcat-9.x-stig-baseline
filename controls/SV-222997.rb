control 'SV-222997' do
  title 'AccessLogValve must be configured for Catalina engine.'
  desc '<Engine> container represents the entire request processing machinery associated with a particular Catalina Service. It receives and processes all requests from one or more connectors, and returns the completed response to the connector for transmission back to the client. The AccessLogValve will log activity for the Catalina service.

Exactly one engine element MUST be nested inside a service element, following all of the corresponding connector elements associated with the service.

'
  desc 'check', 'As an elevated user on the Tomcat server, edit the $CATALINA_BASE/conf/server.xml file.

Review the <Engine> element. Ensure one AccessLog <Valve> element is nested within the engine element. 

If a <Valve className="org.apache.catalina.valves.AccessLogValve" .../> element is not defined, this is a finding.

EXAMPLE:
<Engine name="Standalone" ...>
  ...
  <Valve className="org.apache.catalina.valves.AccessLogValve"
         prefix="catalina_access_log" suffix=".txt"
         pattern="common"/>
  ...
</Engine>'
  desc 'fix', 'As a privileged user on the Tomcat server, edit the $CATALINA_BASE/conf/server.xml file.

Create a <Valve> element that is nested beneath the <Host> element containing an AccessLogValve. 

EXAMPLE:
<Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="false">
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %t %u &quot;%r&quot; %s %b" />
  ...
</Host>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  tag check_id: 'C-24669r985898_chk'
  tag severity: 'medium'
  tag gid: 'V-222997'
  tag rid: 'SV-222997r1016518_rule'
  tag stig_id: 'TCAT-AS-001560'
  tag gtitle: 'SRG-APP-000495-AS-000220'
  tag fix_id: 'F-24658r985899_fix'
  tag satisfies: ['SRG-APP-000495-AS-000220', 'SRG-APP-000381-AS-000089', 'SRG-APP-000499-AS-000224', 'SRG-APP-000504-AS-000229<#text> The']
  tag 'documentable'
  tag legacy: ['SV-111517', 'V-102577']
  tag cci: ['CCI-000172', 'CCI-003938', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1) (b)', 'CM-5 (1)']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  describe 'At least one Valve element of class AccessLogValve must be a nested component in the <Engine> container' do
    subject { tomcat_server_file['//Engine//Valve/@className'] }
    it { should include 'org.apache.catalina.valves.AccessLogValve' }
  end
end
