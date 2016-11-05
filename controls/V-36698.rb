# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36698 - The use of biometrics must be disabled.'
control 'V-36698' do
  impact 0.5
  title 'The use of biometrics must be disabled.'
  desc 'Allowing biometrics may bypass required authentication methods.  Biometrics may only be used as an additional authentication factor where an enhanced strength of identity credential is necessary or desirable.  Additional factors must be met per DoD policy.'
  tag 'stig', 'V-36698'
  tag severity: 'medium'
  tag checkid: 'C-46868r1_chk'
  tag fixid: 'F-44814r1_fix'
  tag version: 'WN12-CC-000075'
  tag ruleid: 'SV-51739r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Biometrics -> "Allow the use of biometrics" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Biometrics\

Value Name: Enabled

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36698
  
    describe registry_key({
      name: 'Enabled',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Policies\Microsoft\Biometrics',
    }) do
      its("Enabled") { should eq 0 }
    end

# STOP_DESCRIBE V-36698

end

