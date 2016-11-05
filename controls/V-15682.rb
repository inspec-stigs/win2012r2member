# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15682 - Attachments must be prevented from being downloaded from RSS feeds.'
control 'V-15682' do
  impact 0.5
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.'
  tag 'stig', 'V-15682'
  tag severity: 'medium'
  tag checkid: 'C-47346r2_chk'
  tag fixid: 'F-45966r1_fix'
  tag version: 'WN12-CC-000105'
  tag ruleid: 'SV-53040r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Prevent downloading of enclosures" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15682
  
    describe registry_key({
      name: 'DisableEnclosureDownload',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Internet Explorer\Feeds',
    }) do
      its("DisableEnclosureDownload") { should eq 1 }
    end

# STOP_DESCRIBE V-15682

end

