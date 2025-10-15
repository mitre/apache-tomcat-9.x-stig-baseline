control 'SV-222930' do
  title 'AccessLogValve must be configured for each application context.'
  desc 'Tomcat has the ability to host multiple contexts (applications) on one physical server by using the <Host><Context> attribute.
    This allows the admin to specify audit log settings on a per application basis.'
  desc 'check', 'As an elevated user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Review for all <Context> elements.

If a <Valve className="org.apache.catalina.valves.AccessLogValve" .../> element is not defined within each <Context> element, this is a finding.

EXAMPLE:

<Context
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="application_name_log" suffix=".txt"
               pattern=""%h %l %t %u &quot;%r&quot; %s %b" />
  ...
/>'
  desc 'fix', 'As a privileged user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Create a <Valve> element that is nested within the <Context> element containing an AccessLogValve.

EXAMPLE:

<Context 
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="application_name_log" suffix=".txt"
               pattern="%h %l %t %u &quot;%r&quot; %s %b" />
  ...
/>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  tag check_id: 'C-24602r426234_chk'
  tag severity: 'medium'
  tag gid: 'V-222930'
  tag rid: 'SV-222930r960765_rule'
  tag stig_id: 'TCAT-AS-000050'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-24591r426235_fix'
  tag legacy: ['SV-111379', 'V-102435']
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000133', 'CCI-000134', 'CCI-000166', 'CCI-000169', 'CCI-000172']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 d', 'AU-3 e', 'AU-10', 'AU-12 a', 'AU-12 c']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  context_count = tomcat_server_file['//Context'].count

  (1..context_count).each do |i|
    describe tomcat_server_file do
      its(["//Context[#{i}]//Valve/@className"]) { should include 'org.apache.catalina.valves.AccessLogValve' }
    end
  end

  if tomcat_server_file['//Context'].empty?
    impact 0.0
    describe "No Context elements were found in #{tomcat_server_file}" do
      skip 'Test Skipped'
    end
  end
end
