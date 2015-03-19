/* Copyright (C) 2012,2013 IBM Corp.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* Test_IO.cpp - Testing the I/O of the important classes of the library
 * (context, keys, ciphertexts).
 */
#include <fstream>
#include <unistd.h>

#include <NTL/ZZX.h>

#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"

#define N_TESTS 3
static long ms[N_TESTS][4] = {
  //nSlots  m   phi(m) ord(2)
  {   2,    7,    6,    3},
  {   6,   31,   30,    5},
  { 256, 4369, 4096,   16}, // gens=129(16),3(!16)
  //  {  378,  5461,  5292, 14}, // gens=3(126),509(3)
  //  {  630,  8191,  8190, 13}, // gens=39(630)
  //  {  600, 13981, 12000, 20}, // gens=10(30),23(10),3(!2)
  //  {  682, 15709, 15004, 22} // gens=5(682)
};

void checkCiphertext(const Ctxt& ctxt, const ZZX& ptxt, const FHESecKey& sk);

// Testing the I/O of the important classes of the library
// (context, keys, ciphertexts).
int main(int argc, char *argv[])
{
  ArgMapping amap;

  long r=1;
  long p=2;
  long c = 2;
  long w = 64;

  amap.arg("p", p, "plaintext base");
  amap.arg("r", r,  "lifting");
  amap.arg("c", c, "number of columns in the key-switching matrices");
  amap.parse(argc, argv);

  long ptxtSpace = power_long(p,r);

  FHEcontext* contexts[N_TESTS];
  FHESecKey*  sKeys[N_TESTS];
  Ctxt*       ctxts[N_TESTS];
  EncryptedArray* eas[N_TESTS];
  vector<ZZX> ptxts[N_TESTS];

  // first loop: generate stuff and write it to cout

  // open file for writing 
  fstream keyFile("iotest.txt", fstream::out|fstream::trunc);
   assert(keyFile.is_open());
  for (long i=0; i<N_TESTS; i++) {
    long m = ms[i][1];

    cout << "Testing IO: m="<<m<<", p^r="<<p<<"^"<<r<<endl;

    contexts[i] = new FHEcontext(m, p, r);
    buildModChain(*contexts[i], ptxtSpace, c);  // Set the modulus chain

    // Output the FHEcontext to file
    writeContextBase(keyFile, *contexts[i]);
    keyFile << *contexts[i] << endl;

    sKeys[i] = new FHESecKey(*contexts[i]);
    const FHEPubKey& publicKey = *sKeys[i];
    sKeys[i]->GenSecKey(w,ptxtSpace); // A Hamming-weight-w secret key
    addSome1DMatrices(*sKeys[i]);// compute key-switching matrices that we need
    eas[i] = new EncryptedArray(*contexts[i]);

    long nslots = eas[i]->size();

    // Output the secret key to file, twice. Below we will have two copies
    // of most things.
    keyFile << *sKeys[i] << endl;;
    keyFile << *sKeys[i] << endl;;
// 
//     vector<ZZX> b;
//     long p2r = eas[i]->getContext().alMod.getPPowR();
//     ZZX poly = RandPoly(0,to_ZZ(p2r)); // choose a random constant polynomial
//     eas[i]->decode(ptxts[i], poly);
// 
//     ctxts[i] = new Ctxt(publicKey);
//     eas[i]->encrypt(*ctxts[i], publicKey, ptxts[i]);
//     eas[i]->decrypt(*ctxts[i], *sKeys[i], b);
//     assert(ptxts[i].size() == b.size());
//     for (long j = 0; j < nslots; j++) assert (ptxts[i][j] == b[j]);
// 
//     // output the plaintext
//     keyFile << "[ ";
//     for (long j = 0; j < nslots; j++) keyFile << ptxts[i][j] << " ";
//     keyFile << "]\n";
// 
//     eas[i]->encode(poly,ptxts[i]);
//     keyFile << poly << endl;
// 
//     // Output the ciphertext to file
//     keyFile << *ctxts[i] << endl;
//     keyFile << *ctxts[i] << endl;
//     cerr << "okay " << i << endl;
  }
  keyFile.close();
  cerr << "so far, so good\n";
}
