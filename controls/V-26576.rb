# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26576 - The IP-HTTPS IPv6 transition technology must be disabled.'
control 'V-26576' do
  impact 0.5
  title 'The IP-HTTPS IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  tag 'stig', 'V-26576'
  tag severity: 'medium'
  tag checkid: 'C-47275r1_chk'
  tag fixid: 'F-45895r1_fix'
  tag version: 'WN12-CC-000008'
  tag ruleid: 'SV-52969r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set IP-HTTPS State" to "Enabled: Disabled State".  

Note: "IPHTTPS URL:" must be entered in the policy even if set to Disabled State.  Enter "about:blank".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface\

Value Name: IPHTTPS_ClientState

Type: REG_DWORD
Value: 3'

# START_DESCRIBE V-26576
  
    describe registry_key({
      name: 'IPHTTPS_ClientState',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface',
    }) do
      its("IPHTTPS_ClientState") { should eq 3 }
    end

# STOP_DESCRIBE V-26576

end

