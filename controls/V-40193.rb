# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40193 - Virtual guest operating systems must be registered in a vulnerability and asset management system.'
control 'V-40193' do
  impact 0.5
  title 'Virtual guest operating systems must be registered in a vulnerability and asset management system.'
  desc 'Virtual guest operating systems share the same vulnerabilities as operating systems running on dedicated hardware and must be individually assessed for security guidance compliance.  The VMS used may be DISA VMS or a similar vulnerability and asset management system.'
  tag 'stig', 'V-40193'
  tag severity: 'medium'
  tag checkid: 'C-46949r1_chk'
  tag fixid: 'F-45176r1_fix'
  tag version: 'WN12-GE-000011'
  tag ruleid: 'SV-52151r2_rule'
  tag fixtext: 'Register all virtual guest operating systems as separate assets in a vulnerability and asset management system.'
  tag checktext: 'If no virtual guest operating systems exist, this is NA.

Determine if virtual guest operating systems have been registered in a vulnerability and asset management system as separate assets.  If they have not, this is a finding.'

# START_DESCRIBE V-40193
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40193

end

