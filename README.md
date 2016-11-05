# Inspec Profile for windows-2012r2 member server STIGs

# _WIP - Not a valid set of checks yet_

Please see this repo's issues for work yet to be done.

# Introduction

Based on Security Guides found at [STIG](http://iase.disa.mil/stigs/Pages/index.aspx)

The Security Technical Implementation Guides (STIGs) and the NSA Guides are the configuration standards for DOD IA and IA-enabled devices/systems. Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the Security Technical Implementation Guides (STIGs). The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

## Develop Inspec checks:

See the parent tools repository at https://github.com/inspec-stigs/inspec-stigs-tools. This repository
uses a modified `read_stig_xml.rb` to auto-generate checks for registry keys. As this is still under heavy development, please note:

- The checks have not been reviewed
- The checks only cover registry keys
- The registry keys are maybe only valid for exact equals checks, not greater than/less than checks
- Our code is crap (but so is all code, so what's new...)

## Demos

### With Test-Kitchen

```
$ kitchen create
...
$ kitchen converge
...
$ kitchen verify
-----> Starting Kitchen (v1.13.2)
-----> Verifying <default-windows-2012r2>...
       Use `/Users/peterburkholder/Projects/inspec-stigs/win2012r2member/test/integration/default` for testing
****.**F*F*****************.*F*.*F.*F*.F....*FF.*F*.FFFFFF.....FFF*FFFFFFF*FFFF*FFFFFFFFFFFFFFFFFF****F*FF*.FFFFF.FFF*FFFF*F*FFF*FFFFFFFF*F*.F*****************************************************************FFFFFFFF*****F*******FFFF...F...*.FF.FFFFFFFFFFFFF*F**FF**F**********FFFFFFFFFFFFFFF**FFFFFF*******FFFFFF***********F**FFFFF**F*FF.*FFFFFF*************************.FF.***

Pending: (Failures listed here are expected and do not affect your suite's status)

  1) File  is a pending example
     # Not yet implemented
     # ./controls/V-1070.rb:23

Failures:

  1) Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System LegalNoticeText
     Failure/Error: its("LegalNoticeText") { should eq See }

     NameError:
       uninitialized constant #<Class:#<#<Class:0x007f812b5962e0>:0x007f812b595b38>>::See
     # ./controls/V-1089.rb:68:in `block (3 levels) in load_with_context'
     # /Users/peterburkholder/.chefdk/gem/ruby/2.3.0/gems/inspec-1.3.0/lib/inspec/runner_rspec.rb:77:in `run'
     # /Users/peterburkholder/.chefdk/gem/ruby/2.3.0/gems/inspec-1.3.0/lib/inspec/runner.rb:112:in `run_tests'
     # /Users/peterburkholder/.chefdk/gem/ruby/2.3.0/gems/inspec-1.3.0/lib/inspec/runner.rb:96:in `run'

...
```

### Direct check against a remote system

```
inspec exec . -t winrm://username@host --password 'password' --format=progress
```
