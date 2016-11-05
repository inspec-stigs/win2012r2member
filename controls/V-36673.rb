# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36673 - IP stateless autoconfiguration limits state must be enabled.'
control 'V-36673' do
  impact 0.1
  title 'IP stateless autoconfiguration limits state must be enabled.'
  desc 'IP stateless autoconfiguration could configure routes that circumvent preferred routes if not limited.'
  tag 'stig', 'V-36673'
  tag severity: 'low'
  tag checkid: 'C-46855r1_chk'
  tag fixid: 'F-44726r1_fix'
  tag version: 'WN12-CC-000011'
  tag ruleid: 'SV-51605r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> Parameters -> "Set IP Stateless Autoconfiguration Limits State" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: EnableIPAutoConfigurationLimits

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36673
  
    describe registry_key({
      name: 'EnableIPAutoConfigurationLimits',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Tcpip\Parameters',
    }) do
      its("EnableIPAutoConfigurationLimits") { should eq 1 }
    end

# STOP_DESCRIBE V-36673

end

