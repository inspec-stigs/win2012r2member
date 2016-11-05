# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3481 - Media Player must be configured to prevent automatic Codec downloads.'
control 'V-3481' do
  impact 0.5
  title 'Media Player must be configured to prevent automatic Codec downloads.'
  desc 'The Windows Media Player uses software components, referred to as Codecs, to play back media files.  By default, when an unknown file type is opened with the Media Player, it will search the Internet for the appropriate Codec and automatically download it.  To ensure platform consistency and to protect against new vulnerabilities associated with media types, all Codecs must be installed by the System Administrator.'
  tag 'stig', 'V-3481'
  tag severity: 'medium'
  tag checkid: 'C-47226r2_chk'
  tag fixid: 'F-45847r1_fix'
  tag version: 'WN12-UC-000013'
  tag ruleid: 'SV-52921r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback -> "Prevent Codec Download" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\WindowsMediaPlayer\

Value Name: PreventCodecDownload

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3481
  
    describe registry_key({
      name: 'PreventCodecDownload',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Policies\Microsoft\WindowsMediaPlayer',
    }) do
      its("PreventCodecDownload") { should eq 1 }
    end

# STOP_DESCRIBE V-3481

end

