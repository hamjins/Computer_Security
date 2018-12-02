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

int main ( int argc, char* argv[] ){
  int aesKeyLength = SHA256::DIGESTSIZE;  //key length 32 bytes = 256 bit key
  byte iv[ CryptoPP::AES::BLOCKSIZE ], key[ aesKeyLength ];
  memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE ); 
  memset( key, 0x00, aesKeyLength ); 
  
  try
    {
      ClientSocket client_socket ( "localhost", 30000 );
      std::string encodeReply, reply;

      try
   {
     char tmp[101], erase[101];
     std::string userInfo, sendInfo, base64encodedciphertext, base64decryptedciphertext; //처음 CLIENT가 쓰는 유저 INFO 
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
