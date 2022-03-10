control 'V-222958' do
  title 'Example applications must be removed.'
  desc '
  Tomcat provides example applications, documentation, and other directories
    in the default installation which do not serve a production use. These
    files must be deleted.
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server OS type the following command:

  sudo ls -l $CATALINA_BASE/webapps/examples.

  If the examples folder exists or contains any content, this is a finding.
  '
  desc 'fix', '
  From the Tomcat server OS type the following command:

   sudo rm -rf $CATALINA_BASE/webapps/examples
  '

  impact 0.5
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-222958'
  tag rid: 'SV-222958r615938_rule'
  tag stig_id: 'TCAT-AS-000560'
  tag fix_id: 'F-24619r426319_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base')
  describe file("#{catalina_base}/webapps/examples") do
    it { should_not exist }
  end
end
