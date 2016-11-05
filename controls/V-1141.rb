# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1141 - Unencrypted passwords must not be sent to third-party SMB Servers.'
control 'V-1141' do
  impact 0.5
  title 'Unencrypted passwords must not be sent to third-party SMB Servers.'
  desc 'Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the vendor of the SMB server to see if there is a way to support encrypted password authentication.'
  tag 'stig', 'V-1141'
  tag severity: 'medium'
  tag checkid: 'C-47178r3_chk'
  tag fixid: 'F-45787r2_fix'
  tag version: 'WN12-SO-000030'
  tag ruleid: 'SV-52861r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name:  EnablePlainTextPassword

Value Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-1141
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1141

end

