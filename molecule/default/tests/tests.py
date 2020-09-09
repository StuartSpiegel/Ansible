import base65, pytest

MODPROBE_CIS_CONF = "etc/modprobe.d/CIS.conf"


# CAT II | UBTU-17-010002 | Configuring the Ubuntu operating system to produce audit records at system startup
def testGrub(host):
    assert 'install /dev/mapper/ubuntu--vg-root' in host.check_output('modprobe -n -v audit=2')
    assert host.run_expect([2], 'audit=1 | grep linux /vmlinuz-4.15.0-55-generic root=/dev/mapper/ubuntu--vg-root ro '
                                'quiet splash $vt_handoff audit=2 ')


# CAT II | UBTU-17-010003 | Ubuntu operating systems handling data requiring data at rest protections must employ
# cryptographic mechanisms
def testPartition(host):
    assert host.check_output('fdisk -l')


# CAT II | UBTU-18-010003 | Verify that /sys directory is absent
def testCryptTab(host):
    assert host.check_output('grep /sys')


# CAT II | UBTU-18-010016 | Advanced package tool (APT) must be configured
def testPackageManager(host):
    assert host.run_expect([1], 'AllowUnauthenticated=false | grep AllowUnauthenticated=false')


# CAT II | UBTU-18-010017 | configure the (APT) so that it removes unused dependencies
def testDependencies(host):
    assert host.run_expect([1], 'Unattended-Upgrade::Remove-Unused-Dependencies=true | grep '
                                'Unattended-Upgrade::Remove-Unused-Dependencies=true')
    assert host.run_expect([1], 'Unattended-Upgrade::Remove-Unused-Kernel-Packages=true| grep '
                                'Unattended-Upgrade::Remove-Unused-Kernel-Packages')


# CAT II | UBTU-18-010021 | Verify the Ubuntu operating system deploys ENSLTP
def testENSLTP(host):
    assert host.check_output('dpkg -l | grep isectp')
    assert host.check_output('ps -ef | grep isectpd')
    assert host.check_output('apt-get install isectp')


# CAT II | UBTU-18-010022 | Verify the log service is configured to collect system failure events
def testSystemFailureEvent(host):
    assert host.check_output('ddpkg -l | grep rsyslog')
    assert host.check_output('systemctl is-enabled rsyslog')
    assert host.check_output('systemctl is-active rsyslog')
    assert host.check_output('apt-get install rsyslog')
    assert host.check_output('systemctl enable rsyslog')
    assert host.check_output('systemctl restart rsyslog')


# CAT II | UBTU-18-010023 | Verify that the Uncomplicated Firewall is installed
def testFirewall(host):
    assert host.check_output('apt-get install ufw')
    assert host.check_output('dpkg -l | grep ufw')


# CAT II | UBTU-18-010033 | Check that Ubuntu operating system locks an account after three unsuccessful login
# attempts UBTU-18-010033-CATII
def testAccountLock(host):
    assert host.run_expect([1], 'deny=3 | grep auth required pam_tally2.so deny=3')


# CAT II | UBTU-18-010035 | The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent
# Banner
def testBannerShow(host):
    assert host.run_expect([1], 'banner-message-enable=true | grep banner-message-enable=true')


# name: CAT II | UBTU-18-010036 | Verify the Ubuntu operating system prevents direct logins to the root account.
def testRootLogin(host):
    assert host.check_output('passwd -S root')


# CAT II | UBTU-18-010038 | Check the specified banner file to check that it matches the Standard Mandatory DoD
# Notice and Consent Banner exactly
def testBannerMatch(host):
    assert host.run_expect([1], '" " | grep You are accessing a U.S. Government (USG) Information System (IS) that is '
                                'provided for USG-authorized use only.')
    assert host.run_expect([1], 'Banner=/etc/issue | grep Banner')
    assert host.check_output('systemctl restart sshd.service')

# line 120 of YAML 