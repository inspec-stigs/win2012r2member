# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1128 - Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'
control 'V-1128' do
  impact 0.1
  title 'Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'
  desc 'Security configuration tools such as Group Policies and Security Templates allow system administrators to consolidate security-related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows machines.'
  tag 'stig', 'V-1128'
  tag severity: 'low'
  tag checkid: 'C-47176r2_chk'
  tag fixid: 'F-45785r1_fix'
  tag version: 'WN12-00-000013'
  tag ruleid: 'SV-52859r2_rule'
  tag fixtext: 'Implement a process using security configuration tools or the equivalent to configure Windows systems to meet security requirements.'
  tag checktext: 'Verify security configuration tools or equivalent processes are being used to configure Windows systems to meet security requirements.  If security configuration tools or equivalent processes are not used, this is a finding.

Security configuration tools that are integrated into Windows, such as Group Policies and Security Templates, may be used to configure platforms for security compliance.

If an alternate method is used to configure a system (e.g., manually using the DISA Windows Security STIGs, etc.) and the same configured result is achieved, this is acceptable.'

# START_DESCRIBE V-1128
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1128

end

