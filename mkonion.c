/*
	diskonion - a layered deniable disk encryption scheme
	Copyright (C) 2012 Edward Cree
	
	This library is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this library.  If not, see <http://www.gnu.org/licenses/>.
	
	In addition, as a special exception, the copyright holders give
	permission to link the code of portions of this program with the
	OpenSSL library under certain conditions as described in each
	individual source file, and distribute linked combinations
	including the two.
	
	You must obey the GNU General Public License in all respects
	for all of the code used other than OpenSSL.  If you modify
	file(s) with this exception, you may extend this exception to your
	version of the file(s), but you are not obligated to do so.  If you
	do not wish to do so, delete this exception statement from your
	version.  If you delete this exception statement from all source
	files in the program, then also delete it here.
	
	mkonion.c: create an empty onion volume (possibly onto an existing "keystream file")
*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "crypto.h"
#include "onion.h"
#include "bits.h"

#define SECTOR_KEY_LENGTH	(SECTOR_LENGTH-0x10) // should be 4064
#define SECTOR_KEY_STRIDE	13 // coprime to 4064

int main(int argc, char *argv[])
{
	size_t sz=0;
	const char *outfile=NULL;
	for(int arg=1;arg<argc;arg++)
	{
		if(strncmp(argv[arg], "-s", 2)==0)
		{
			if(sscanf(argv[arg]+2, "%zu", &sz)!=1)
			{
				fprintf(stderr, "Bad -s, `%s' not numeric\n", argv[arg]+2);
				return(1);
			}
		}
		else if(strncmp(argv[arg], "-ks", 3)==0)
		{
			size_t ksz;
			if(sscanf(argv[arg]+3, "%zu", &ksz)!=1)
			{
				fprintf(stderr, "Bad -ks, `%s' not numeric\n", argv[arg]+3);
				return(1);
			}
			sz=ksz<<10;
		}
		else if(strncmp(argv[arg], "-Ms", 3)==0)
		{
			size_t Msz;
			if(sscanf(argv[arg]+3, "%zu", &Msz)!=1)
			{
				fprintf(stderr, "Bad -Ms, `%s' not numeric\n", argv[arg]+3);
				return(1);
			}
			sz=Msz<<20;
		}
		else if(strncmp(argv[arg], "-Gs", 3)==0)
		{
			size_t Gsz;
			if(sscanf(argv[arg]+3, "%zu", &Gsz)!=1)
			{
				fprintf(stderr, "Bad -Gs, `%s' not numeric\n", argv[arg]+3);
				return(1);
			}
			sz=Gsz<<30;
		}
		else if(strcmp(argv[arg], "+s")==0)
			sz=0;
		else if(strncmp(argv[arg], "-o", 2)==0)
			outfile=argv[arg]+2;
	}
	if(!outfile)
	{
		fprintf(stderr, "Must supply -o<outfile>\n");
		return(1);
	}
	struct stat st_buf;
	if(stat(outfile, &st_buf))
	{
		if(!sz)
		{
			perror("Failed to stat outfile: stat");
			return(1);
		}
	}
	else if(sz)
	{
		if(sz!=(size_t)st_buf.st_size)
		{
			fprintf(stderr, "Size mismatch; volume is %zu bytes\n", (size_t)st_buf.st_size);
			return(1);
		}
	}
	else
		sz=st_buf.st_size;
	int outfd=open(outfile, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR);
	if(outfd<0)
	{
		perror("Failed to open outfile: open");
		return(1);
	}
	fprintf(stderr, "Image size is %zu bytes\n", sz);
	if(sz%BLOCK_LENGTH)
	{
		fprintf(stderr, "Error - image size not a multiple of BLOCK_LENGTH %zu\n", BLOCK_LENGTH);
		return(1);
	}
	size_t nblk=sz/BLOCK_LENGTH-1;
	fprintf(stderr, "Image has %zu blocks\n", nblk);
	fprintf(stderr, "Enter your layer master passphrase (at most %u bytes will be used)\n", KEY_LENGTH_HIGH);
	unsigned char passphrase[KEY_LENGTH_HIGH+1];
	memset(passphrase, 0, KEY_LENGTH_HIGH); // make sure it's initialised to all 0s
	if(!fgets((char *)passphrase, KEY_LENGTH_HIGH+1, stdin))
	{
		perror("Failed to read passphrase: fgets");
		return(1);
	}
	unsigned char sectorkey[SECTOR_KEY_LENGTH];
	fprintf(stderr, "Generating sector key, you may need to supply some entropy to the system\n");
	int e=generate_key_data(SECTOR_KEY_LENGTH, sectorkey);
	if(e)
	{
		if(e<0) perror("generate_key_data");
		else fprintf(stderr, "generate_key_data failed with code %d\n", e);
		return(1);
	}
	fprintf(stderr, "Preparing header sector\n");
	unsigned char headersector[SECTOR_LENGTH];
	write32be(BLOCK_LENGTH, headersector);
	write32be(KEY_LENGTH_HIGH, headersector+0x4);
	write32be(SECTOR_KEY_LENGTH, headersector+0x8);
	write32be(SECTOR_KEY_STRIDE, headersector+0xC);
	memcpy(headersector+0x10, sectorkey, SECTOR_KEY_LENGTH);
	fprintf(stderr, "Writing header sector\n");
	unsigned char iv[IV_LENGTH];
	if((e=generate_iv(iv)))
	{
		if(e<0) perror("generate_iv");
		else fprintf(stderr, "generate_iv failed with code %d\n", e);
		return(1);
	}
	unsigned char block[BLOCK_LENGTH];
	memcpy(block, iv, IV_LENGTH);
	if((e=encrypt_sector(KEY_LENGTH_HIGH, passphrase, iv, headersector, block+IV_LENGTH)))
	{
		if(e<0) perror("encrypt_sector");
		else fprintf(stderr, "encrypt_sector failed with code %d\n", e);
		return(1);
	}
	if((e=writeall(outfd, block, BLOCK_LENGTH))!=BLOCK_LENGTH)
	{
		if(e<0) perror("writeall");
		else fprintf(stderr, "writeall failed, returned %d\n", e);
		return(1);
	}
	fprintf(stderr, "Writing sector blocks\n");
	unsigned char blanksector[SECTOR_LENGTH];
	memset(blanksector, 0, SECTOR_LENGTH);
	unsigned char derivedkey[KEY_LENGTH_HIGH];
	for(size_t blk=0;blk<nblk;blk++)
	{
		if((blk&1023)==1023)
		{
			fputc('.', stderr);
			fflush(stderr);
		}
		if((e=generate_iv(iv)))
		{
			fprintf(stderr, "Error on block %zu:\n", blk);
			if(e<0) perror("generate_iv");
			else fprintf(stderr, "generate_iv failed with code %d\n", e);
			return(1);
		}
		memcpy(block, iv, IV_LENGTH);
		if((e=derive_key(SECTOR_KEY_LENGTH, sectorkey, KEY_LENGTH_HIGH, derivedkey, SECTOR_KEY_STRIDE, blk)))
		{
			fprintf(stderr, "Error on block %zu:\n", blk);
			if(e<0) perror("derive_key");
			else fprintf(stderr, "derive_key failed with code %d\n", e);
			return(1);
		}
		if((e=encrypt_sector(KEY_LENGTH_HIGH, derivedkey, iv, blanksector, block+IV_LENGTH)))
		{
			fprintf(stderr, "Error on block %zu:\n", blk);
			if(e<0) perror("encrypt_sector");
			else fprintf(stderr, "encrypt_sector failed with code %d\n", e);
			return(1);
		}
		if((e=writeall(outfd, block, BLOCK_LENGTH))!=BLOCK_LENGTH)
		{
			fprintf(stderr, "Error on block %zu:\n", blk);
			if(e<0) perror("writeall");
			else fprintf(stderr, "writeall failed, returned %d\n", e);
			return(1);
		}
	}
	fprintf(stderr, "Finished creating the image, all OK\n");
	return(0);
}
