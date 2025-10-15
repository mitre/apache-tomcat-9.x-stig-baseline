control 'SV-222951' do
  title 'The shutdown port must be disabled.'
  desc 'Tomcat listens on TCP port 8005 to accept shutdown requests. By connecting to this port and sending the SHUTDOWN command, all applications within Tomcat are halted. The shutdown port is not exposed to the network as it is bound to the loopback interface. Set the shutdown attribute in $CATALINA_BASE/conf/server.xml.'
  desc 'check', 'From the Tomcat server run the following OS command:

$ sudo grep -i shutdown $CATALINA_BASE/conf/server.xml

Ensure the server shutdown port attribute in $CATALINA_BASE/conf/server.xml is set to -1. 

EXAMPLE:
<Server port="-1" shutdown="SHUTDOWN">

If Server port not = "-1" shutdown="SHUTDOWN", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, edit the $CATALINA_BASE/conf/server.xml file: set the Server port setting to -1 and restart the Tomcat server.

<Server port="-1" shutdown="SHUTDOWN">

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  tag check_id: 'C-24623r426297_chk'
  tag severity: 'medium'
  tag gid: 'V-222951'
  tag rid: 'SV-222951r960963_rule'
  tag stig_id: 'TCAT-AS-000490'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24612r426298_fix'
  tag 'documentable'
  tag legacy: ['SV-111427', 'V-102485']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  shutdown_port = tomcat_server_file['//Server/@port']

  describe shutdown_port do
    it { should cmp '-1' }
  end
end
