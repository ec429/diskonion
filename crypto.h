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
	
	crypto.h: crypto functions abstraction layer
*/

#include <sys/types.h>
#include <openssl/aes.h>

// These lengths are in bytes (not bits as is common in many crypto contexts)
#define BLOCK_LENGTH	512
#define IV_LENGTH		AES_BLOCK_SIZE
#define KS_BLKLEN		(IV_LENGTH/2)
#define SECTOR_LENGTH	(BLOCK_LENGTH-IV_LENGTH)
#define KEY_LENGTH_LOW	16
#define KEY_LENGTH_MED	24
#define KEY_LENGTH_HIGH	32

// For these functions, a return of 0 indicates success, positive indicates failure, and negative indicates failure with errno set
int generate_iv(unsigned char *iv); // generates a random IV and stores it in iv (whose length should be IV_LENGTH).  Uses /dev/urandom
int generate_newiv(const unsigned char *iv, unsigned char *newiv); // generates a random new IV with the same keystream as iv and stores it in newiv.  Uses /dev/urandom
int generate_key_data(size_t key_len, unsigned char *key); // generates random key data of length key_len bytes and stores it in key.  Uses /dev/random
int encrypt_sector(size_t key_len, unsigned char *restrict key, const unsigned char *restrict iv, unsigned char *restrict sector_in, unsigned char *restrict sector_out); // encrypts a sector of length SECTOR_LENGTH using the specified key and IV, storing the result in sector_out (which should also be of length SECTOR_LENGTH, ie. the IV is not prepended).  key_len is in BYTES
int decrypt_sector(size_t key_len, unsigned char *restrict key, const unsigned char *restrict iv, unsigned char *restrict sector_in, unsigned char *restrict sector_out); // decrypts a sector of length SECTOR_LENGTH using the specified key and IV, storing the result in sector_out.  key_len is in BYTES
