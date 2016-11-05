# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3380 - The system must be configured to force users to log off when their allowed logon hours expire.'
control 'V-3380' do
  impact 0.5
  title 'The system must be configured to force users to log off when their allowed logon hours expire.'
  desc 'Limiting logon hours can help protect data by only allowing access during specified times.  This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, this must be enforced.'
  tag 'stig', 'V-3380'
  tag severity: 'medium'
  tag checkid: 'C-47210r2_chk'
  tag fixid: 'F-45819r1_fix'
  tag version: 'WN12-SO-000066'
  tag ruleid: 'SV-52893r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Force logoff when logon hours expire" to "Enabled".'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Network security: Force logoff when logon hours expire" is not set to "Enabled", this is a finding.'

# START_DESCRIBE V-3380
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-3380

end

