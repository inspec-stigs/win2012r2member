# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36679 - Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.'
control 'V-36679' do
  impact 0.5
  title 'Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.'
  desc 'Compromised boot drivers can introduce malware prior to some protection mechanisms that load after initialization.  The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application.  At a minimum, drivers determined to be bad must not be allowed.'
  tag 'stig', 'V-36679'
  tag severity: 'medium'
  tag checkid: 'C-46859r1_chk'
  tag fixid: 'F-44729r1_fix'
  tag version: 'WN12-CC-000027'
  tag ruleid: 'SV-51608r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware -> "Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Policies\EarlyLaunch\

Value Name: DriverLoadPolicy

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36679
  
    describe registry_key({
      name: 'DriverLoadPolicy',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Policies\EarlyLaunch',
    }) do
      its("DriverLoadPolicy") { should eq 1 }
    end

# STOP_DESCRIBE V-36679

end

