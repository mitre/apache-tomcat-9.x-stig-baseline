control 'SV-222939' do
  title 'Date and time of events must be logged.'
  desc 'The access logfile format is defined within a Valve that implements the org.apache.catalina.valves.AccessLogValve interface within the /opt/tomcat/server.xml configuration file: The %t pattern code is included in the pattern element and logs the date and time of the event. Including the date pattern in the log configuration provides useful information about the time of the event which is critical for troubleshooting and forensic investigations.'
  desc 'check', 'As an elevated user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Review all "Valve" elements.

If the pattern= statement does not include %t, this is a finding.

EXAMPLE:
<Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="false">
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %t %u &quot;%r&quot; %s %b" />
  ...
</Host>'
  desc 'fix', 'As a privileged user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Modify the <Valve> element(s) nested within the <Host> element(s).  

Change the AccessLogValve setting to include %t in the pattern= statement. 

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
  tag check_id: 'C-24611r426261_chk'
  tag severity: 'medium'
  tag gid: 'V-222939'
  tag rid: 'SV-222939r960894_rule'
  tag stig_id: 'TCAT-AS-000240'
  tag gtitle: 'SRG-APP-000096-AS-000059'
  tag fix_id: 'F-24600r426262_fix'
  tag 'documentable'
  tag legacy: ['SV-111407', 'V-102461']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  access_log_valves = tomcat_server_file['//Valve/@className'].reject { |name| !name.include? 'org.apache.catalina.valves.AccessLogValve' }
  patterns = tomcat_server_file['//Valve/@pattern'].reject { |pattern| !pattern.include? '%t' }

  describe 'Each Valve element of class AccessLogValve must have the "%t" included in the pattern in order to log date and time of events in the log file' do
    subject { access_log_valves.count }
    it { should cmp patterns.count }
  end
end
