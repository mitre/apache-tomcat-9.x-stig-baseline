control 'V-222988' do
  title '$CATALINA_BASE/logs/ folder must be owned by tomcat user, group tomcat.'
  desc '
  Tomcat file permissions must be restricted. The standard configuration is
    to have all Tomcat files owned by root with group Tomcat. While root has
    read/write privileges, group only has read permissions, and world has no
    permissions. The exceptions are the logs, temp, and work directories that
    are owned by the Tomcat user rather than root. This means that even if an
    attacker compromises the Tomcat process, they cannot change the Tomcat
    configuration, deploy new web applications, or modify existing web
    applications. The Tomcat process runs with a umask of 0027 to maintain
    these permissions.
  '
  desc 'rationale', ''

  desc 'check', '
  Access the Tomcat server from the command line and execute the following OS
    command:

  sudo find $CATALINA_BASE/logs -follow -maxdepth 0 \\(  ! -user tomcat -o !
    -group tomcat \\) -ls

  If ISSM risk acceptance specifies deviation from requirement based on
    operational/application needs, this is not a finding if the permissions are
    set in accordance with the risk acceptance.

  If no folders are displayed, this is not a finding.

  If results indicate the $CATALINA_BASE/logs folder ownership and group
    membership is not set to tomcat:tomcat, this is a finding.
  '
  desc 'fix', '
  If operational/application requirements specify different group file
    permissions, obtain ISSM risk acceptance and set permissions according to
    risk acceptance.

  Run the following commands on the Tomcat server:

  sudo find $CATALINA_BASE/logs -maxdepth 0 \\( ! -user tomcat \\) | sudo
    xargs chown tomcat

  sudo find $CATALINA_BASE/logs -maxdepth 0 \\( ! -group tomcat \\) | sudo
    xargs chgrp tomcat
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-222988'
  tag rid: 'SV-222988r754843_rule'
  tag stig_id: 'TCAT-AS-001250'
  tag fix_id: 'F-24649r426409_fix'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  catalina_base = input('catalina_base')
  tomcat_logs_dir = file("#{catalina_base}/logs")
  describe tomcat_logs_dir do
    its('owner') { should cmp 'tomcat' }
    its('group') { should cmp 'tomcat' }
  end
end
