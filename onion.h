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
	
	onion.h: diskonion common functions
*/

#include <stdlib.h>

int derive_key(size_t data_len, const unsigned char *restrict data, size_t key_len, unsigned char *restrict key, size_t stride, size_t index); // derives a key according to the "derived sector key" rules
int decode_keystream(const unsigned char *restrict iv, unsigned char *restrict ks); // decodes the IV_LENGTH/2 byte keystream block from the IV
int encode_keystream(const unsigned char *restrict ks, unsigned char *restrict iv); // creates a new IV encoding the given keystream block
