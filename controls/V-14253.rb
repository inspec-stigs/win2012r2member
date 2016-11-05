# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14253 - Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
control 'V-14253' do
  impact 0.5
  title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
  desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  tag 'stig', 'V-14253'
  tag severity: 'medium'
  tag checkid: 'C-47294r3_chk'
  tag fixid: 'F-45914r2_fix'
  tag version: 'WN12-CC-000064-MS'
  tag ruleid: 'SV-52988r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call -> "Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-14253
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-14253

end

