#include "ClientSocket.h"
#include "SocketException.h"
#include <iostream>
#include <string>
#include <sstream> //For std::ostringstream

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
#include <stdexcept>
using std::runtime_error;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/dh.h"
using CryptoPP::DH;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularExponentiation;
#include "cryptopp/base64.h" 
#include "cryptopp/aes.h" 
#include "cryptopp/filters.h" 
#include "cryptopp/modes.h" //Crypto++

/*
 대칭키(AES 암호화를 할 key)를 diffie-hellman을 이용하여 생성하자!(인증과정을 거치는것과 동일하다)
 1. Integer 데이터형(매우 큰 정수를 담기 위한 Crypto++의 class)을 string으로 변환한 후 클라이언트가 서버에게 공용키 g, p, q를 건넨다.
 2. g, p, q를 건네받은 서버는 다시 Integer형으로 변환 후, 자신의 Diffie-Hellman public key(g^b)와 private key(b)를 생성한다.
 3. 연산을 마친 client, server는 각각 g^a와 g^b를 건넨다.
 4. 데이터형 변환 후 secret Key를 서로 연산하고, 값이 맞는지 비교(agree)한다.
 5. 맞다면 key를 AES암호화에 이용한다. 아니라면, 로그인이 불가능하게 된다.
 
*/
std::string ToString(const CryptoPP::Integer&);

void UnsignedIntegerToByteBlock(const Integer& x, SecByteBlock& bytes)
{
    size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
    bytes.resize(encodedSize);
    x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
}

int main ( int argc, char* argv[] ){
  byte iv[ CryptoPP::AES::BLOCKSIZE ]; 
  int aesKeyLength = SHA256::DIGESTSIZE;  //key length 32 bytes = 256 bit key

  try
    {
      ClientSocket client_socket ( "localhost", 30000 );

      // RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
      // http://tools.ietf.org/html/rfc5114#section-2.1
	Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
		  "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
		  "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
		  "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		  "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
		  "DF1FB2BC2E4A4371");

	Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
		  "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
		  "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
		  "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
		  "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
		  "855E6EEB22B3B2E5");

	Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

      std::string encodeReply, reply;
      AutoSeededRandomPool rndA;
      DH dhA;
      dhA.AccessGroupParameters().Initialize(p, q, g);

      if(!dhA.GetGroupParameters().ValidateGroup(rndA, 3))
		throw runtime_error("Failed to validate prime and generator");


      /*
      Schnorr Group 소수는 p = rq + 1, p 및 q 소수의 형식입니다. 하위 그룹 순서를 제공합니다. 1024 비트 MODP 그룹의 경우 보안 수준은         
      80 비트입니다 (160 비트 소수 오더 하위 그룹 기준).
      최대 보안 레벨을 사용하는 비교 / 대비에 대해서는 dh-agree.zip을 참조하십시오. http://www.cryptopp.com/wiki/Diffie-Hellman을 참조하십시오.
      및 http://www.cryptopp.com/wiki/Security_level을 참조하십시오.
      */
      p = dhA.GetGroupParameters().GetModulus();
      q = dhA.GetGroupParameters().GetSubgroupOrder();
      g = dhA.GetGroupParameters().GetGenerator();
		
      Integer v = ModularExponentiation(g, q, p);
	if(v != Integer::One())
	  throw runtime_error("Failed to verify order of the subgroup");
   
      SecByteBlock privA(dhA.PrivateKeyLength());
      SecByteBlock pubA(dhA.PublicKeyLength());
      SecByteBlock secretKeyA(dhA.AgreedValueLength());

      // Generate a pair of integers for Alice. The public integer is forwarded to Bob.
      dhA.GenerateKeyPair(rndA, privA, pubA);

      client_socket << ToString(p);
      client_socket << ToString(g);
      client_socket << ToString(q);
      Integer integerPubA; //SecByteBlcok to Integer - B에게 공유할 공유키 g^a
      integerPubA.Decode(pubA.BytePtr(), pubA.SizeInBytes());

      std::string strPubB;

      client_socket << ToString(integerPubA); //서버에게 건넬 공유키 g^a
      client_socket >> strPubB;  //클라이언트가 받을 공유키 g^b

      Integer intPubB(strPubB.c_str());

      SecByteBlock pubB;
      UnsignedIntegerToByteBlock(intPubB, pubB);

      if (!dhA.Agree(secretKeyA, privA, pubB)) { std::cout << "DH key Exchange Error!" <<"\n"; return 0;}

      //AES암호화 과정의 KEY는 Diffie-Hellman에서 만들어낸 secret key를 이용한다.
      SecByteBlock key(SHA256::DIGESTSIZE);
      SHA256().CalculateDigest(key, secretKeyA, secretKeyA.size());
      memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE ); 
   
      try
   {
     char tmp[101], erase[101];
     std::string userInfo, sendInfo, base64decryptedciphertext, base64encodedciphertext; //처음 CLIENT가 쓰는 유저 INFO 
     std::cout << "username: ";
     scanf("%s",tmp); userInfo = tmp;

     userInfo.append("\t");

     std::cout << "password: ";
     scanf("%s",tmp); userInfo.append(tmp);
     
     CryptoPP::AES::Encryption aesEncryption (key, aesKeyLength);
     CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption (aesEncryption, iv);

     CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(sendInfo));

     stfEncryptor.Put(reinterpret_cast<const unsigned char*>(userInfo.c_str()), userInfo.length()+1);
     stfEncryptor.MessageEnd();

     CryptoPP::StringSource(sendInfo, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64encodedciphertext)));
     //client_socket에 들어간 id, pw를 Server에 보냄
     client_socket << base64encodedciphertext;
  
    //Server에서 보낸 제곱값 받음
     client_socket >> encodeReply;
     if(encodeReply == "false" || encodeReply == "falsefalse") {
      std::cout << "인증 실패!" << "\n";
      return 0;
      }

     CryptoPP::StringSource(encodeReply, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink( base64decryptedciphertext)));

     CryptoPP::AES::Decryption aesDecryption (key, aesKeyLength);
     CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption (aesDecryption, iv);

     CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(reply));
     stfDecryptor.Put(reinterpret_cast<const unsigned char*>(base64decryptedciphertext.c_str()), base64decryptedciphertext.size());
     stfDecryptor.MessageEnd();

   }
      catch ( SocketException& ) {}

      std::cout << "We received this response from the server: " << reply << "\n";

    }
  catch ( SocketException& e )
    {
      std::cout << "Exception was caught:" << e.description() << "\n";
    }

  return 0;
}

std::string ToString(const CryptoPP::Integer& n) {
    // Send the CryptoPP::Integer to the output stream string
    std::ostringstream os;
    os << n;    
    // or, if required:
    //     os << std::hex << n;  

    // Convert the stream to std::string
    return os.str();
}
