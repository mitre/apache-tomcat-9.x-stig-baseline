control 'V-222934' do
  title 'DefaultServlet must be set to readonly for PUT and DELETE.'
  desc '
  The DefaultServlet is a servlet provided with Tomcat. It is called when no
    other suitable page can be displayed to the client. The DefaultServlet
    serves static resources as well as directory listings and is declared
    globally in $CATALINA_BASE/conf/web.xml. By default, Tomcat behaves as if
    the DefaultServlet is set to "true" (HTTP commands like PUT and DELETE
    are rejected). However, the readonly parameter is not in the web.xml file
    by default so to ensure proper configuration and system operation, the
    "readonly" parameter in web.xml  must be created and set to "true".
    Creating the setting in web.xml provides assurances the system is operating
    as required. Changing the readonly parameter to false could allow clients
    to delete or modify static resources on the server and upload new
    resources.
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server run the following command:

  sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A5 -B2 defaultservlet

  If the "readonly" param-value for the "DefaultServlet" servlet class =
    "false" or does not exist, this is a finding.
  '
  desc 'fix', '
  From the Tomcat server console as a privileged user:

  Edit the $CATALINA_BASE/conf/web.xml file.

  If the "readonly" param-value does not exist, it must be created.

  Ensure the "readonly" param-value for the "DefaultServlet" servlet
    class = "true".
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-0000241'
  tag gid: 'V-222934'
  tag rid: 'SV-222934r615938_rule'
  tag stig_id: 'TCAT-AS-000090'
  tag fix_id: 'F-24595r622486_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  catalina_base = input('catalina_base')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml")
  servlets = tomcat_web_file['//servlet/servlet-class']

  servlet_index = servlets.index('org.apache.catalina.servlets.DefaultServlet') + 1
  params = tomcat_web_file["//servlet[#{servlet_index}]/init-param/param-name"]

  if params.index('readonly').nil?
    describe 'The readonly param for DefaultServlet is not defined' do
      subject { params.index('readonly') }
      it { should_not be_nil }
    end

  else
    params_index = params.index('readonly') + 1
    readonly = tomcat_web_file["//servlet[#{servlet_index}]/init-param[#{params_index}]/param-value"]

    describe 'The readonly param for the DefaultServlet element must be set to true' do
      subject { readonly }
      it { should cmp 'true' }
    end
  end
end
