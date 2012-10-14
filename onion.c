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
	
	onion.c: diskonion common functions
*/

#include "onion.h"
#include "crypto.h"

int derive_key(size_t data_len, const unsigned char *restrict data, size_t key_len, unsigned char *restrict key, size_t stride, size_t index)
{
	if(!data) return(1);
	if(!key) return(2);
	size_t R=(stride*(index%data_len))%data_len; // this should avoid overflow as long as stride*data_len fits in a size_t, which it should (since stride<data_len<=4064)
	for(size_t i=0;i<key_len;i++)
		key[i]=data[(R+i)%data_len];
	return(0);
}

int decode_keystream(const unsigned char *restrict iv, unsigned char *restrict ks)
{
	if(!iv) return(1);
	if(!ks) return(2);
	for(size_t i=0;i<IV_LENGTH/2;i++)
		ks[i]=iv[i<<1]^iv[(i<<1)|1];
	return(0);
}

int encode_keystream(const unsigned char *restrict ks, unsigned char *restrict iv)
{
	if(!iv) return(3);
	if(!ks) return(4);
	for(size_t i=0;i<IV_LENGTH/2;i++)
	{
		iv[i<<1]=ks[i];
		iv[(i<<1)|1]=0;
	}
	return(generate_newiv(iv, iv));
}
