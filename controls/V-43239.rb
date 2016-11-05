# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-43239 - Command line data must be prevented from inclusion in process creation events (Windows 2012 R2).'
control 'V-43239' do
  impact 0.5
  title 'Command line data must be prevented from inclusion in process creation events (Windows 2012 R2).'
  desc 'When enabled, the Windows policy setting, "Include command line in process creation events", will save all command line entries details to the event log.  This could potentially include passwords saved in clear text, which must be prevented.'
  tag 'stig', 'V-43239'
  tag severity: 'medium'
  tag checkid: 'C-57999r1_chk'
  tag fixid: 'F-62325r1_fix'
  tag version: 'WN12-CC-000139'
  tag ruleid: 'SV-56344r2_rule'
  tag fixtext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> "Include command line in process creation events" to "Disabled".'
  tag checktext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE 
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\

Value Name:  ProcessCreationIncludeCmdLine_Enabled

Value Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-43239
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-43239

end

