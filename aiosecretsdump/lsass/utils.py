
from pypykatz.lsadecryptor.packages.msv.decryptor import LogonSession

def mimi_to_grep(mimi):
	res = ':'.join(LogonSession.grep_header) + '\r\n'
	for luid in mimi.logon_sessions:
		for row in mimi.logon_sessions[luid].to_grep_rows():
			res += ':'.join(row) + '\r\n'
			for cred in mimi.orphaned_creds:
				t = cred.to_dict()
				if t['credtype'] != 'dpapi':
					if t['password'] is not None:
						x =  [str(t['credtype']), str(t['domainname']), str(t['username']), '', '', '', '', '', str(t['password'])]
						res += ':'.join(x) + '\r\n'
				else:
					t = cred.to_dict()
					x = [str(t['credtype']), '', '', '', '', '', str(t['masterkey']), str(t['sha1_masterkey']), str(t['key_guid']), '']
					res += ':'.join(x) + '\r\n'

	return res