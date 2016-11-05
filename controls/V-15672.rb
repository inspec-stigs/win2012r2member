# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15672 - Event Viewer Events.asp links must be turned off.'
control 'V-15672' do
  impact 0.1
  title 'Event Viewer Events.asp links must be turned off.'
  desc 'Viewing events is a function of administrators, who must not access the internet with privileged accounts.  This setting will disable  Events.asp hyperlinks in Event Viewer to prevent links to the internet from within events.'
  tag 'stig', 'V-15672'
  tag severity: 'low'
  tag checkid: 'C-47324r2_chk'
  tag fixid: 'F-45944r1_fix'
  tag version: 'WN12-CC-000033'
  tag ruleid: 'SV-53017r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Event Viewer "Events.asp" links" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\EventViewer\

Value Name: MicrosoftEventVwrDisableLinks

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15672
  
    describe registry_key({
      name: 'MicrosoftEventVwrDisableLinks',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\EventViewer',
    }) do
      its("MicrosoftEventVwrDisableLinks") { should eq 1 }
    end

# STOP_DESCRIBE V-15672

end

