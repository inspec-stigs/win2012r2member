# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36709 - Basic authentication for RSS feeds over HTTP must be turned off.'
control 'V-36709' do
  impact 0.5
  title 'Basic authentication for RSS feeds over HTTP must be turned off.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  tag 'stig', 'V-36709'
  tag severity: 'medium'
  tag checkid: 'C-46878r1_chk'
  tag fixid: 'F-44824r1_fix'
  tag version: 'WN12-CC-000106'
  tag ruleid: 'SV-51749r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Turn on Basic feed authentication over HTTP" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: AllowBasicAuthInClear

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36709
  
    describe registry_key({
      name: 'AllowBasicAuthInClear',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Internet Explorer\Feeds',
    }) do
      its("AllowBasicAuthInClear") { should eq 0 }
    end

# STOP_DESCRIBE V-36709

end

