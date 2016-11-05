# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4113 - The system must be configured to limit how often keep-alive packets are sent.'
control 'V-4113' do
  impact 0.1
  title 'The system must be configured to limit how often keep-alive packets are sent.'
  desc 'This setting controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact.  A higher value could allow an attacker to cause a denial of service with numerous connections.'
  tag 'stig', 'V-4113'
  tag severity: 'low'
  tag checkid: 'C-47232r2_chk'
  tag fixid: 'F-45853r2_fix'
  tag version: 'WN12-SO-000041'
  tag ruleid: 'SV-52927r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" to "300000 or 5 minutes (recommended)" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: KeepAliveTime

Value Type: REG_DWORD
Value: 300000 (or less)'

# START_DESCRIBE V-4113
  
    describe registry_key({
      name: 'KeepAliveTime',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Tcpip\Parameters',
    }) do
      its("KeepAliveTime") { should eq 300000 }
    end

# STOP_DESCRIBE V-4113

end

