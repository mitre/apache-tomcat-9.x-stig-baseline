control 'V-222947' do
  title 'Jar files in the $CATALINA_HOME/bin/ folder must have their permissions set to 640.'
  desc '
  Tomcat\'s file permissions must be restricted. The standard configuration is
    to have all Tomcat files owned by root with the group Tomcat. While root
    has read/write privileges, tomcat group only has read permissions, and
    world has no permissions. The exceptions are the logs, temp, and work
    directories that are owned by the Tomcat user rather than root. This means
    that even if an attacker compromises the Tomcat process, they cannot change
    the Tomcat configuration, deploy new web applications, or modify existing
    web applications. The Tomcat process runs with a umask of 0027 to maintain
    these permissions.
  '
  desc 'rationale', ''

  desc 'check', '
  Access the Tomcat server from the command line and execute the following OS
    command:

  sudo find $CATALINA_HOME/bin/*jar -follow -maxdepth 0 -type f  \\( \\!
    -perm 640 \\) -ls

  If there are no results, or if .sh extensions are found, this is not a
    finding.

  If results indicate any of the jar file permissions contained in the
    $CATALINA_HOME/bin folder are not set to 640, this is a finding.
  '
  desc 'fix', '
  Run the following command on the Tomcat server:

  sudo find $CATALINA_HOME/bin/*jar -follow -maxdepth 0 -type f -print0 |
    sudo xargs chmod 640 $CATALINA_HOME/bin/*jar
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag gid: 'V-222947'
  tag rid: 'SV-222947r754840_rule'
  tag stig_id: 'TCAT-AS-000380'
  tag fix_id: 'F-24608r426286_fix'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9']

  catalina_base = input('catalina_base')
  tomcat_bin_files = command("ls #{catalina_base}/bin").stdout.split
  non_compliant_files = tomcat_bin_files.select { |bin| file("#{catalina_base}/bin/#{bin}").more_permissive_than?('0640') }
  jar_files = non_compliant_files.reject { |bin| File.extname(bin) != '.jar' }

  describe 'Files in the $CATALINA_BASE/bin/ directory must have their permissions set to 640' do
    subject { jar_files }
    it { should be_empty }
  end
end
