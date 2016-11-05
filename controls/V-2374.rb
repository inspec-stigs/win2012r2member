# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-2374 - Autoplay must be disabled for all drives.'
control 'V-2374' do
  impact 1.0
  title 'Autoplay must be disabled for all drives.'
  desc 'Allowing Autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon media is inserted into the drive.  As a result, the setup file of programs or music on audio media may start.  By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives.  Enabling this policy disables Autoplay on all drives.'
  tag 'stig', 'V-2374'
  tag severity: 'high'
  tag checkid: 'C-47196r2_chk'
  tag fixid: 'F-45805r1_fix'
  tag version: 'WN12-CC-000074'
  tag ruleid: 'SV-52879r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Turn off AutoPlay" to "Enabled:All Drives".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\

Value Name: NoDriveTypeAutoRun

Type: REG_DWORD
Value: 0x000000ff (255)'

# START_DESCRIBE V-2374
  
    describe registry_key({
      name: 'NoDriveTypeAutoRun',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer',
    }) do
      its("NoDriveTypeAutoRun") { should eq 0x000000ff }
    end

# STOP_DESCRIBE V-2374

end

