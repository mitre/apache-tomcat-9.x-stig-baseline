control 'V-222949' do
  title 'Tomcat user UMASK must be set to 0027.'
  desc '
  For Unix-based systems, umask settings affect file creation permissions. If
    the permissions are too loose, newly created log files and applications
    could be accessible to unauthorized users via the file system.  Ensure the
    Tomcat OS user account has the correct file creation permission settings by
    validating the OS umask settings for the Tomcat user. Setting umask to 0027
    gives the Tomcat user full rights, group users r-x permission and all
    others no access. Tomcat will most likely be running as a systemd service.
    Locate the systemd service file for Tomcat. The default location for the
    link to the service file is in /etc/systemd/system folder. The service file
    name should be indicative of the Tomcat process so tomcat.service is the
    logical name for the service file and is the name referenced by the STIG.
  '
  desc 'rationale', ''

  desc 'check', '
  Reference the system documentation and make relevant changes to the
    following commands if the system differs:

  From the Tomcat server command line run the following command:

  sudo cat /etc/systemd/system/tomcat.service | grep -i umask

  If the umask is not = 0027, this is a finding.
  '
  desc 'fix', '
  From the Tomcat server as a privileged user:

  Use a file editor like nano or vi and edit the
    /etc/systemd/system/tomcat.service file.

  Change the "UMask=" setting to 0027.

  UMask =0027

  Save the file and restart Tomcat:
  sudo systemctl restart tomcat
  sudo systemctl daemon-reload
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag gid: 'V-222949'
  tag rid: 'SV-222949r615938_rule'
  tag stig_id: 'TCAT-AS-000450'
  tag fix_id: 'F-24610r426292_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  if virtualization.system.eql?('docker')
    describe 'Virtualization system used is Docker' do
      skip 'The virtualization system used to validate content is Docker. The systemd program is not installed in containers, therefore this check will be skipped.'
    end
  else
    describe 'The systemd startup file must exist' do
      subject { service('tomcat') }
      it { should be_installed }
    end

    unless service('tomcat').params.empty?
      describe service('tomcat').params do
        its('UMask') { should cmp '0027' }
      end
    end
  end
end
