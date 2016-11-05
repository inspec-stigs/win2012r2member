# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21950 - The service principal name (SPN) target name validation level must be turned off.'
control 'V-21950' do
  impact 0.5
  title 'The service principal name (SPN) target name validation level must be turned off.'
  desc 'If a service principle name (SPN) is provided by the client, it is validated against the servers list of SPNs.  Implementation may disrupt file and print sharing capabilities.'
  tag 'stig', 'V-21950'
  tag severity: 'medium'
  tag checkid: 'C-47481r1_chk'
  tag fixid: 'F-46101r1_fix'
  tag version: 'WN12-SO-000035'
  tag ruleid: 'SV-53175r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Server SPN target name validation level" to "Off".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Services\LanmanServer\Parameters\

Value Name: SmbServerNameHardeningLevel

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21950
  
    describe registry_key({
      name: 'SmbServerNameHardeningLevel',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanmanServer\Parameters',
    }) do
      its("SmbServerNameHardeningLevel") { should eq 0 }
    end

# STOP_DESCRIBE V-21950

end

