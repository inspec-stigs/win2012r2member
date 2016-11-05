# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36710 - Automatic download of updates from the Windows Store must be turned off.'
control 'V-36710' do
  impact 0.1
  title 'Automatic download of updates from the Windows Store must be turned off.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially allow sensitive information outside of the enterprise.  Application updates must be obtained from an internal source.'
  tag 'stig', 'V-36710'
  tag severity: 'low'
  tag checkid: 'C-58003r1_chk'
  tag fixid: 'F-62329r2_fix'
  tag version: 'WN12-CC-000109'
  tag ruleid: 'SV-51750r2_rule'
  tag fixtext: 'The Windows Store is not installed by default.  If the \Windows\WinStore directory does not exist, this is NA.

Windows 2012 R2:
Windows 2012 R2 split the original policy that configures this setting into two separate ones.  Configuring either one to "Enabled" will update the registry value as identified in the Check section.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> 
"Turn off Automatic Download of updates on Win8 machines" or "Turn off Automatic Download and install of updates" to "Enabled".

Windows 2012:
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> "Turn off Automatic Download of updates" to "Enabled".'
  tag checktext: 'The Windows Store is not installed by default.  If the \Windows\WinStore directory does not exist, this is NA.
If the following registry value does not exist or is not configured as specified, this is a finding:

Windows 2012 R2:
Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\WindowsStore\

Value Name:  AutoDownload

Type:  REG_DWORD
Value:  0x00000002 (2)

Windows 2012:
Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate\

Value Name:  AutoDownload

Type:  REG_DWORD
Value:  0x00000002 (2)'

# START_DESCRIBE V-36710
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36710

end

