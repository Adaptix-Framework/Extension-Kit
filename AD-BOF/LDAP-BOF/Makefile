# LDAP BOF Collection Makefile
CC = x86_64-w64-mingw32-gcc
STRIP = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I _include -I src/common -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF -c

all: bof

bof: clean
	@mkdir -p _bin/LDAP && echo 'creating _bin/LDAP directory'
	@$(CC) $(CFLAGS) src/get/get-users.c -o _bin/LDAP/get-users.x64.o && $(STRIP) _bin/LDAP/get-users.x64.o && echo '[+] get-users' || echo '[!] get-users'
	@$(CC) $(CFLAGS) src/get/get-computers.c -o _bin/LDAP/get-computers.x64.o && $(STRIP) _bin/LDAP/get-computers.x64.o && echo '[+] get-computers' || echo '[!] get-computers'
	@$(CC) $(CFLAGS) src/get/get-groups.c -o _bin/LDAP/get-groups.x64.o && $(STRIP) _bin/LDAP/get-groups.x64.o && echo '[+] get-groups' || echo '[!] get-groups'
	@$(CC) $(CFLAGS) src/get/get-usergroups.c -o _bin/LDAP/get-usergroups.x64.o && $(STRIP) _bin/LDAP/get-usergroups.x64.o && echo '[+] get-usergroups' || echo '[!] get-usergroups'
	@$(CC) $(CFLAGS) src/get/get-groupmembers.c -o _bin/LDAP/get-groupmembers.x64.o && $(STRIP) _bin/LDAP/get-groupmembers.x64.o && echo '[+] get-groupmembers' || echo '[!] get-groupmembers'
	@$(CC) $(CFLAGS) src/get/get-object.c -o _bin/LDAP/get-object.x64.o && $(STRIP) _bin/LDAP/get-object.x64.o && echo '[+] get-object' || echo '[!] get-object'
	@$(CC) $(CFLAGS) src/get/get-domaininfo.c -o _bin/LDAP/get-domaininfo.x64.o && $(STRIP) _bin/LDAP/get-domaininfo.x64.o && echo '[+] get-domaininfo' || echo '[!] get-domaininfo'
	@$(CC) $(CFLAGS) src/get/get-maq.c -o _bin/LDAP/get-maq.x64.o && $(STRIP) _bin/LDAP/get-maq.x64.o && echo '[+] get-maq' || echo '[!] get-maq'
	@$(CC) $(CFLAGS) src/get/get-writable.c -o _bin/LDAP/get-writable.x64.o && $(STRIP) _bin/LDAP/get-writable.x64.o && echo '[+] get-writable' || echo '[!] get-writable'
	@$(CC) $(CFLAGS) src/get/get-delegation.c -o _bin/LDAP/get-delegation.x64.o && $(STRIP) _bin/LDAP/get-delegation.x64.o && echo '[+] get-delegation' || echo '[!] get-delegation'
	@$(CC) $(CFLAGS) src/get/get-uac.c -o _bin/LDAP/get-uac.x64.o && $(STRIP) _bin/LDAP/get-uac.x64.o && echo '[+] get-uac' || echo '[!] get-uac'
	@$(CC) $(CFLAGS) src/get/get-attribute.c -o _bin/LDAP/get-attribute.x64.o && $(STRIP) _bin/LDAP/get-attribute.x64.o && echo '[+] get-attribute' || echo '[!] get-attribute'
	@$(CC) $(CFLAGS) src/get/get-spn.c -o _bin/LDAP/get-spn.x64.o && $(STRIP) _bin/LDAP/get-spn.x64.o && echo '[+] get-spn' || echo '[!] get-spn'
	@$(CC) $(CFLAGS) src/get/get-acl.c -o _bin/LDAP/get-acl.x64.o && $(STRIP) _bin/LDAP/get-acl.x64.o && echo '[+] get-acl' || echo '[!] get-acl'
	@$(CC) $(CFLAGS) src/get/get-rbcd.c -o _bin/LDAP/get-rbcd.x64.o && $(STRIP) _bin/LDAP/get-rbcd.x64.o && echo '[+] get-rbcd' || echo '[!] get-rbcd'
	@$(CC) $(CFLAGS) src/add/add-user.c -o _bin/LDAP/add-user.x64.o && $(STRIP) _bin/LDAP/add-user.x64.o && echo '[+] add-user' || echo '[!] add-user'
	@$(CC) $(CFLAGS) src/add/add-computer.c -o _bin/LDAP/add-computer.x64.o && $(STRIP) _bin/LDAP/add-computer.x64.o && echo '[+] add-computer' || echo '[!] add-user'
	@$(CC) $(CFLAGS) src/add/add-group.c -o _bin/LDAP/add-group.x64.o && $(STRIP) _bin/LDAP/add-group.x64.o && echo '[+] add-group' || echo '[!] add-user'
	@$(CC) $(CFLAGS) src/add/add-groupmember.c -o _bin/LDAP/add-groupmember.x64.o && $(STRIP) _bin/LDAP/add-groupmember.x64.o && echo '[+] add-groupmember' || echo '[!] add-groupmember'
	@$(CC) $(CFLAGS) src/add/add-ou.c -o _bin/LDAP/add-ou.x64.o && $(STRIP) _bin/LDAP/add-ou.x64.o && echo '[+] add-ou' || echo '[!] add-ou'
	@$(CC) $(CFLAGS) src/add/add-sidhistory.c -o _bin/LDAP/add-sidhistory.x64.o && $(STRIP) _bin/LDAP/add-sidhistory.x64.o && echo '[+] add-sidhistory' || echo '[!] add-sidhistory'
	@$(CC) $(CFLAGS) src/add/add-spn.c -o _bin/LDAP/add-spn.x64.o && $(STRIP) _bin/LDAP/add-spn.x64.o && echo '[+] add-spn' || echo '[!] add-spn'
	@$(CC) $(CFLAGS) src/add/add-attribute.c -o _bin/LDAP/add-attribute.x64.o && $(STRIP) _bin/LDAP/add-attribute.x64.o && echo '[+] add-attribute' || echo '[!] add-attribute'
	@$(CC) $(CFLAGS) src/add/add-uac.c -o _bin/LDAP/add-uac.x64.o && $(STRIP) _bin/LDAP/add-uac.x64.o && echo '[+] add-uac' || echo '[!] add-uac'
	@$(CC) $(CFLAGS) src/add/add-delegation.c -o _bin/LDAP/add-delegation.x64.o && $(STRIP) _bin/LDAP/add-delegation.x64.o && echo '[+] add-delegation' || echo '[!] add-delegation'
	@$(CC) $(CFLAGS) src/add/add-rbcd.c -o _bin/LDAP/add-rbcd.x64.o && $(STRIP) _bin/LDAP/add-rbcd.x64.o && echo '[+] add-rbcd' || echo '[!] add-rbcd'
	@$(CC) $(CFLAGS) src/add/add-ace.c -o _bin/LDAP/add-ace.x64.o && $(STRIP) _bin/LDAP/add-ace.x64.o && echo '[+] add-ace' || echo '[!] add-ace'
	@$(CC) $(CFLAGS) src/set/set-password.c -o _bin/LDAP/set-password.x64.o && $(STRIP) _bin/LDAP/set-password.x64.o && echo '[+] set-password' || echo '[!] set-password'
	@$(CC) $(CFLAGS) src/set/set-password-auth.c -o _bin/LDAP/set-password-auth.x64.o && $(STRIP) _bin/LDAP/set-password-auth.x64.o && echo '[+] set-password-auth' || echo '[!] set-password-auth'
	@$(CC) $(CFLAGS) src/set/set-spn.c -o _bin/LDAP/set-spn.x64.o && $(STRIP) _bin/LDAP/set-spn.x64.o && echo '[+] set-spn' || echo '[!] set-spn'
	@$(CC) $(CFLAGS) src/set/set-delegation.c -o _bin/LDAP/set-delegation.x64.o && $(STRIP) _bin/LDAP/set-delegation.x64.o && echo '[+] set-delegation' || echo '[!] set-delegation'
	@$(CC) $(CFLAGS) src/set/set-attribute.c -o _bin/LDAP/set-attribute.x64.o && $(STRIP) _bin/LDAP/set-attribute.x64.o && echo '[+] set-attribute' || echo '[!] set-attribute'
	@$(CC) $(CFLAGS) src/set/set-uac.c -o _bin/LDAP/set-uac.x64.o && $(STRIP) _bin/LDAP/set-uac.x64.o && echo '[+] set-uac' || echo '[!] set-uac'
	@$(CC) $(CFLAGS) src/set/set-owner.c -o _bin/LDAP/set-owner.x64.o && $(STRIP) _bin/LDAP/set-owner.x64.o && echo '[+] set-owner' || echo '[!] set-owner'
	@$(CC) $(CFLAGS) src/move/move-object.c -o _bin/LDAP/move-object.x64.o && $(STRIP) _bin/LDAP/move-object.x64.o && echo '[+] move-object' || echo '[!] move-object'
	@$(CC) $(CFLAGS) src/remove/remove-groupmember.c -o _bin/LDAP/remove-groupmember.x64.o && $(STRIP) _bin/LDAP/remove-groupmember.x64.o && echo '[+] remove-groupmember' || echo '[!] remove-groupmember'
	@$(CC) $(CFLAGS) src/remove/remove-object.c -o _bin/LDAP/remove-object.x64.o && $(STRIP) _bin/LDAP/remove-object.x64.o && echo '[+] remove-object' || echo '[!] remove-object'
	@$(CC) $(CFLAGS) src/remove/remove-delegation.c -o _bin/LDAP/remove-delegation.x64.o && $(STRIP) _bin/LDAP/remove-delegation.x64.o && echo '[+] remove-delegation' || echo '[!] remove-delegation'
	@$(CC) $(CFLAGS) src/remove/remove-spn.c -o _bin/LDAP/remove-spn.x64.o && $(STRIP) _bin/LDAP/remove-spn.x64.o && echo '[+] remove-spn' || echo '[!] remove-spn'
	@$(CC) $(CFLAGS) src/remove/remove-attribute.c -o _bin/LDAP/remove-attribute.x64.o && $(STRIP) _bin/LDAP/remove-attribute.x64.o && echo '[+] remove-attribute' || echo '[!] remove-attribute'
	@$(CC) $(CFLAGS) src/remove/remove-rbcd.c -o _bin/LDAP/remove-rbcd.x64.o && $(STRIP) _bin/LDAP/remove-rbcd.x64.o && echo '[+] remove-rbcd' || echo '[!] remove-rbcd'
	@$(CC) $(CFLAGS) src/remove/remove-ace.c -o _bin/LDAP/remove-ace.x64.o && $(STRIP) _bin/LDAP/remove-ace.x64.o && echo '[+] remove-ace' || echo '[!] remove-ace'
	@$(CC) $(CFLAGS) src/remove/remove-uac.c -o _bin/LDAP/remove-uac.x64.o && $(STRIP) _bin/LDAP/remove-uac.x64.o && echo '[+] remove-uac' || echo '[!] remove-uac'

clean:
	@rm -rf _bin/LDAP
