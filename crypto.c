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
	
	crypto.c: crypto functions abstraction layer
*/

#include "crypto.h"
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef INSUFFICIENTLY_PARANOID
#define STRONG_RAND	"/dev/urandom"
#else
#define STRONG_RAND	"/dev/random"
#endif

int generate_iv(unsigned char *iv)
{
	if(!iv) return(1);
	int fd=open("/dev/urandom", O_RDONLY);
	if(fd<0)
		return(-1);
	size_t i=0;
	ssize_t b;
	while(i<IV_LENGTH)
	{
		b=read(fd, iv+i, IV_LENGTH-i);
		if(b<=0) break;
		i+=b;
	}
	close(fd);
	if(b<0) return(-2);
	if(!b) return(2);
	return(0);
}

int generate_key_data(size_t key_len, unsigned char *key)
{
	if(!key_len) return(3);
	if(!key) return(1);
	int fd=open(STRONG_RAND, O_RDONLY);
	if(fd<0)
		return(-1);
	size_t i=0;
	size_t d=0;
	ssize_t b;
	while(i<key_len)
	{
		b=read(fd, key+i, key_len-i);
		if(b<=0) break;
		i+=b;
		while(i>(d<<7))
		{
			fputc('.', stderr);
			fflush(stderr);
			d++;
		}
	}
	close(fd);
	if(b<0) return(-2);
	if(!b) return(2);
	return(0);
}

int encrypt_sector(size_t key_len, unsigned char *restrict key, unsigned char *restrict iv, unsigned char *restrict sector_in, unsigned char *restrict sector_out)
{
	AES_KEY akey;
	if(AES_set_encrypt_key(key, key_len<<3, &akey)) return(1);
	AES_cbc_encrypt(sector_in, sector_out, SECTOR_LENGTH, &akey, iv, AES_ENCRYPT);
	return(0);
}

int decrypt_sector(size_t key_len, unsigned char *restrict key, unsigned char *restrict iv, unsigned char *restrict sector_in, unsigned char *restrict sector_out)
{
	AES_KEY akey;
	if(AES_set_decrypt_key(key, key_len<<3, &akey)) return(1);
	AES_cbc_encrypt(sector_in, sector_out, SECTOR_LENGTH, &akey, iv, AES_DECRYPT);
	return(0);
}
