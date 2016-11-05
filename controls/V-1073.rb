# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1073 - Systems must be maintained at a supported service pack level.'
control 'V-1073' do
  impact 1.0
  title 'Systems must be maintained at a supported service pack level.'
  desc 'Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities, which leave them subject to exploitation.  Systems must be maintained at a service pack level supported by the vendor with new security updates.'
  tag 'stig', 'V-1073'
  tag severity: 'high'
  tag checkid: 'C-47495r1_chk'
  tag fixid: 'F-46115r1_fix'
  tag version: 'WN12-GE-000001'
  tag ruleid: 'SV-53189r2_rule'
  tag fixtext: 'Update the system to a supported release or service pack level.'
  tag checktext: 'Run "winver.exe". 

If the "About Windows" dialog box does not display 
"Microsoft Windows Server 
Version 6.2 (Build 9200)"
or greater, this is a finding. 
      
No preview versions will be used in a production environment. 

Unsupported Service Packs/Releases:
Windows 2012 - any release candidates or versions prior to the initial release.'

# START_DESCRIBE V-1073
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1073

end

