control 'V-222986' do
  title '$CATALINA_HOME folder must be owned by the root user, group tomcat.'
  desc '
  Tomcat file permissions must be restricted. The standard configuration is
    to have the folder where Tomcat is installed owned by the root user with
    the group set to tomcat. The $CATALINA_HOME environment variable should be
    set to the location of the root directory of the "binary" distribution of
    Tomcat.
  '
  desc 'rationale', ''

  desc 'check', '
  Access the Tomcat server from the command line and execute the following OS
    command:

  sudo find $CATALINA_HOME -follow -maxdepth 0 \\(  ! -user root -o ! -group
    tomcat \\) -ls

  If no folders are displayed, this is not a finding.

  If results indicate the $CATALINA_HOME folder ownership and group
    membership is not set to root:tomcat, this is a finding.
  '
  desc 'fix', '
  Run the following commands on the Tomcat server:

  sudo find $CATALINA_HOME -maxdepth 0 \\( ! -user root \\) | sudo xargs
    chown root

  sudo find $CATALINA_HOME -maxdepth 0 \\( ! -group tomcat \\) | sudo xargs
    chgrp tomcat
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-222986'
  tag rid: 'SV-222986r615938_rule'
  tag stig_id: 'TCAT-AS-001200'
  tag fix_id: 'F-24647r426403_fix'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  catalina_base = input('catalina_base')
  tomcat_dir = file(catalina_base)
  describe tomcat_dir do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'tomcat' }
  end
end
