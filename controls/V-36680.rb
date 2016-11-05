# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36680 - Access to the Windows Store must be turned off.'
control 'V-36680' do
  impact 0.5
  title 'Access to the Windows Store must be turned off.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  Turning off access to the Windows Store will limit access to publicly available applications.'
  tag 'stig', 'V-36680'
  tag severity: 'medium'
  tag checkid: 'C-69279r1_chk'
  tag fixid: 'F-74883r1_fix'
  tag version: 'WN12-CC-000030'
  tag ruleid: 'SV-51609r2_rule'
  tag fixtext: 'If the \Windows\WinStore directory exists, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off access to the Store" to "Enabled".   

Alternately, uninstall the "Desktop Experience" feature from Windows 2012.  This is located under "User Interfaces and Infrastructure" in the "Add Roles and Features Wizard".  The \Windows\WinStore directory may need to be manually deleted after this.'
  tag checktext: 'The Windows Store is not installed by default. If the \Windows\WinStore directory does not exist, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\

Value Name: NoUseStoreOpenWith

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36680
  
    describe registry_key({
      name: 'NoUseStoreOpenWith',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Policies\Microsoft\Windows\Explorer',
    }) do
      its("NoUseStoreOpenWith") { should eq 1 }
    end

# STOP_DESCRIBE V-36680

end

