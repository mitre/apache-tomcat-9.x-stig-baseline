control 'V-102603' do
  title "AccessLogValve must be configured per each virtual host.\n"
  desc  "Application servers utilize role-based access controls in order to
specify the individuals who are allowed to configure application component
loggable events. The application server must be configured to select which
personnel are assigned the role of selecting which loggable events are to be
logged.


  "
  desc  'rationale', ''
  desc  'check', "
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Review for all $Host elements.

    If a <Valve className=\"org.apache.catalina.valves.AccessLogValve\" .../>
element is not nested within each $Host element, this is a finding.

    EXAMPLE:
    <Host name=\"localhost\" appBase=\"webapps\"
     unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\"
     prefix=\"localhost_access_log\" suffix=\".txt\"
     pattern=\"%h %l %t %u \"%r\" %s %b\" />
     ...
    </Host>
  "
  desc 'fix', "
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Create a <Valve> element that is nested beneath the $Host element
containing an AccessLogValve.

    EXAMPLE:
    <Host name=\"localhost\" appBase=\"webapps\"
     unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\"
     prefix=\"localhost_access_log\" suffix=\".txt\"
     pattern=\"%h %l %t %u \"%r\" %s %b\" />
     ...
    </Host>

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-AS-000051'
  tag satisfies: %w(SRG-APP-000090-AS-000051 SRG-APP-000095-AS-000056
SRG-APP-000100-AS-000063 SRG-APP-000101-AS-000072
SRG-APP-000503-AS-000228 SRG-APP-000505-AS-000230
SRG-APP-000506-AS-000231)
  tag gid: 'V-102603'
  tag rid: 'SV-111549r1_rule'
  tag stig_id: 'TCAT-AS-000180'
  tag fix_id: 'F-108135r2_fix'
  tag cci: %w(CCI-000130 CCI-000135 CCI-000171 CCI-000172
CCI-001487)
  tag nist: ['AU-3', 'AU-3 (1)', 'AU-12 b', 'AU-12 c', 'AU-3']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  if tomcat_server_file['//Host'].empty?
    impact 0.0
    describe "No Context elements were found in #{tomcat_server_file}" do
      skip 'Test Skipped'
    end
  else
    host_count = tomcat_server_file['//Host'].count

    (1..host_count).each do |i|
      describe tomcat_server_file do
        its(["//Host[#{i}]//Valve/@className"]) { should include 'org.apache.catalina.valves.AccessLogValve' }
      end
    end
  end
end
