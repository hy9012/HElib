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

  FHEcontext* contexts;
  FHESecKey*  sKeys;
  Ctxt*       ctxts;
  EncryptedArray* eas;
  vector<ZZX> ptxts;


  // first loop: generate stuff and write it to cout

  // open file for writing 
  fstream keyFile("iotest.txt", fstream::out|fstream::trunc);
   assert(keyFile.is_open());
    long m = ms[2][1];

    cout << "Testing IO: m="<<m<<", p^r="<<p<<"^"<<r<<endl;

    contexts = new FHEcontext(m, p, r);
    buildModChain(*contexts, ptxtSpace, c);  // Set the modulus chain

    // Output the FHEcontext to file
    writeContextBase(keyFile, *contexts);
    keyFile << *contexts << endl;

    sKeys = new FHESecKey(*contexts);
    const FHEPubKey& publicKey = *sKeys;
    sKeys->GenSecKey(w,ptxtSpace); // A Hamming-weight-w secret key
    addSome1DMatrices(*sKeys);// compute key-switching matrices that we need
    eas = new EncryptedArray(*contexts);

    long nslots = eas->size();
    PlaintextArray randomPta(*eas);
    randomPta.random();
    randomPta.print(cout);

    // Output the secret key to file, twice. Below we will have two copies
    // of most things.
    keyFile << *sKeys << endl;;

    vector<ZZX> b;
    long p2r = eas->getContext().alMod.getPPowR();
    ZZX poly = RandPoly(0,to_ZZ(p2r)); // choose a random constant polynomial
    eas->encode(poly, randomPta);
    eas->decode(ptxts, poly);

    ctxts = new Ctxt(publicKey);
    eas->encrypt(*ctxts, publicKey, ptxts);
    eas->decrypt(*ctxts, *sKeys, b);
    assert(ptxts.size() == b.size());
    for (long j = 0; j < nslots; j++) assert (ptxts[j] == b[j]);

    // output the plaintext
    keyFile << "[ ";
    for (long j = 0; j < nslots; j++) keyFile << ptxts[j] << " ";
    keyFile << "]\n";

    eas->encode(poly,ptxts);
    keyFile << poly << endl;

    // Output the ciphertext to file
    keyFile << *ctxts << endl;
    cerr << "okay"<< endl;
  keyFile.close();
  cerr << "so far, so good\n";
}
