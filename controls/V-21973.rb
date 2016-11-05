# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21973 - Autoplay must be turned off for non-volume devices.'
control 'V-21973' do
  impact 1.0
  title 'Autoplay must be turned off for non-volume devices.'
  desc 'Allowing Autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as media is inserted into the drive.  As a result, the setup file of programs or music on audio media may start.  This setting will disable Autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).'
  tag 'stig', 'V-21973'
  tag severity: 'high'
  tag checkid: 'C-47432r1_chk'
  tag fixid: 'F-46052r1_fix'
  tag version: 'WN12-CC-000072'
  tag ruleid: 'SV-53126r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Disallow Autoplay for non-volume devices" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-21973
  
    describe registry_key({
      name: 'NoAutoplayfornonVolume',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Explorer',
    }) do
      its("NoAutoplayfornonVolume") { should eq 1 }
    end

# STOP_DESCRIBE V-21973

end

