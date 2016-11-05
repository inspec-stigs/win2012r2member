# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1151 - The print driver installation privilege must be restricted to administrators.'
control 'V-1151' do
  impact 0.1
  title 'The print driver installation privilege must be restricted to administrators.'
  desc 'Allowing users to install drivers can introduce malware or cause the instability of a system.  Print driver installation should be restricted to administrators.'
  tag 'stig', 'V-1151'
  tag severity: 'low'
  tag checkid: 'C-46960r2_chk'
  tag fixid: 'F-45233r2_fix'
  tag version: 'WN12-SO-000089'
  tag ruleid: 'SV-52214r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Prevent users from installing printer drivers" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\

Value Name: AddPrinterDrivers

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-1151
  
    describe registry_key({
      name: 'AddPrinterDrivers',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers',
    }) do
      its("AddPrinterDrivers") { should eq 1 }
    end

# STOP_DESCRIBE V-1151

end

