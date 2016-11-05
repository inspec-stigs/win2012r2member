# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15698 - The configuration of wireless devices using Windows Connect Now must be disabled.'
control 'V-15698' do
  impact 0.5
  title 'The configuration of wireless devices using Windows Connect Now must be disabled.'
  desc 'Windows Connect Now allows the discovery and configuration of devices over wireless.  Wireless devices must be managed.  If a rogue device is connected to a system, there is potential for sensitive information to be compromised.'
  tag 'stig', 'V-15698'
  tag severity: 'medium'
  tag checkid: 'C-47391r2_chk'
  tag fixid: 'F-46011r1_fix'
  tag version: 'WN12-CC-000012'
  tag ruleid: 'SV-53085r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Configuration of wireless settings using Windows Connect Now" to "Disabled".'
  tag checktext: 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WCN\Registrars\

Value Name: DisableFlashConfigRegistrar
Value Name: DisableInBand802DOT11Registrar
Value Name: DisableUPnPRegistrar
Value Name: DisableWPDRegistrar
Value Name: EnableRegistrars

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15698
  
    describe registry_key({
      name: 'DisableFlashConfigRegistrar',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WCN\Registrars',
    }) do
      its("DisableFlashConfigRegistrar") { should eq 0 }
    end

# STOP_DESCRIBE V-15698

end

