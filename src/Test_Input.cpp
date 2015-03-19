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
  fstream keyFile("iotest.txt", fstream::in);
  for (long i=0; i<N_TESTS; i++) {

    // Read context from file
    unsigned long m1, p1, r1;
    readContextBase(keyFile, m1, p1, r1);
    FHEcontext tmpContext(m1, p1, r1);
    keyFile >> tmpContext;
    //assert (*contexts[i] == tmpContext);
    //cerr << i << ": context matches input\n";

    // We define some things below wrt *contexts[i], not tmpContext.
    // This is because the various operator== methods check equality of
    // references, not equality of the referenced FHEcontext objects.
     //FHEcontext& context;
     FHESecKey secretKey;
     FHESecKey secretKey2(tmpContext);
//     const FHEPubKey& publicKey = secretKey;
     const FHEPubKey& publicKey2 = secretKey2;
// 
     keyFile >> secretKey;
     keyFile >> secretKey2;
//     assert(secretKey == *sKeys[i]);
//     cerr << "   secret key matches input\n";
// 
//     EncryptedArray ea(context);
     EncryptedArray ea2(tmpContext);
// 
     long nslots = ea2.size();
// 
     // Read the plaintext from file
     vector<ZZX> a;
     a.resize(nslots);
     //assert(nslots == (long)ptxts[i].size());
     seekPastChar(keyFile, '['); // defined in NumbTh.cpp
     for (long j = 0; j < nslots; j++) {
       keyFile >> a[j];
       //assert(a[j] == ptxts[i][j]);
     }
    seekPastChar(keyFile, ']');
    cerr << "   ptxt matches input\n";
// 
//     // Read the encoded plaintext from file
    ZZX poly1, poly2;
    keyFile >> poly1;
    eas[i]->encode(poly2,a);
    assert(poly1 == poly2);
    cerr << "   eas[i].encode(a)==poly1 okay\n";
// 
//     ea.encode(poly2,a);
//     assert(poly1 == poly2);
//     cerr << "   ea.encode(a)==poly1 okay\n";
// 
//     ea2.encode(poly2,a);
//     assert(poly1 == poly2);
//     cerr << "   ea2.encode(a)==poly1 okay\n";
// 
//     eas[i]->decode(a,poly1);
//     assert(nslots == (long)a.size());
//     for (long j = 0; j < nslots; j++) assert(a[j] == ptxts[i][j]);
//     cerr << "   eas[i].decode(poly1)==ptxts[i] okay\n";
// 
//     ea.decode(a,poly1);
//     assert(nslots == (long)a.size());
//     for (long j = 0; j < nslots; j++) assert(a[j] == ptxts[i][j]);
//     cerr << "   ea.decode(poly1)==ptxts[i] okay\n";
// 
//     ea2.decode(a,poly1);
//     assert(nslots == (long)a.size());
//     for (long j = 0; j < nslots; j++) assert(a[j] == ptxts[i][j]);
//     cerr << "   ea2.decode(poly1)==ptxts[i] okay\n";
// 
//     // Read ciperhtext from file
//     Ctxt ctxt(publicKey);
//     Ctxt ctxt2(publicKey2);
//     keyFile >> ctxt;
//     keyFile >> ctxt2;
//     assert(ctxts[i]->equalsTo(ctxt,/*comparePkeys=*/false));
//     cerr << "   ctxt matches input\n";
// 
//     sKeys[i]->Decrypt(poly2,*ctxts[i]);
//     assert(poly1 == poly2);
//     cerr << "   sKeys[i]->decrypt(*ctxts[i]) == poly1 okay\n";
// 
//     secretKey.Decrypt(poly2,*ctxts[i]);
//     assert(poly1 == poly2);
//     cerr << "   secretKey.decrypt(*ctxts[i]) == poly1 okay\n";
// 
//     secretKey.Decrypt(poly2,ctxt);
//     assert(poly1 == poly2);
//     cerr << "   secretKey.decrypt(ctxt) == poly1 okay\n";
// 
//     secretKey2.Decrypt(poly2,ctxt2);
//     assert(poly1 == poly2);
//     cerr << "   secretKey2.decrypt(ctxt2) == poly1 okay\n";
// 
//     eas[i]->decrypt(ctxt, *sKeys[i], a);
//     assert(nslots == (long)a.size());
//     for (long j = 0; j < nslots; j++) assert(a[j] == ptxts[i][j]);
//     cerr << "   eas[i].decrypt(ctxt, *sKeys[i])==ptxts[i] okay\n";
// 
//     ea.decrypt(ctxt, secretKey, a);
//     assert(nslots == (long)a.size());
//     for (long j = 0; j < nslots; j++) assert(a[j] == ptxts[i][j]);
//     cerr << "   ea.decrypt(ctxt, secretKey)==ptxts[i] okay\n";
// 
//     ea2.decrypt(ctxt2, secretKey2, a);
//     assert(nslots == (long)a.size());
//     for (long j = 0; j < nslots; j++) assert(a[j] == ptxts[i][j]);
//     cerr << "   ea2.decrypt(ctxt2, secretKey2)==ptxts[i] okay\n";
// 
//     cerr << "test "<<i<<" okay\n\n";
  }
  //unlink("iotest.txt"); // clean up before exiting
}
