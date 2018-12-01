#include "ServerSocket.h"
#include "SocketException.h"
#include <string>
#include <iostream>
#include <fstream> //istream이나 ostream클래스보다 지원하는기능 더 많음. 각각을 상속받은것이 ifstream과 ofstream 
#include <vector>
#include <algorithm>
#include <math.h>
#include <sstream>

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
#include <stdexcept>
using std::runtime_error;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "cryptopp/dh.h"
using CryptoPP::DH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/modes.h" 
#include "cryptopp/dh2.h"
#include "cryptopp/aes.h" 
#include "cryptopp/filters.h" 
#include "cryptopp/base64.h"

std::string ToString(const CryptoPP::Integer&);

void UnsignedIntegerToByteBlock(const Integer& x, SecByteBlock& bytes)
{
    size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
    bytes.resize(encodedSize);
    x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
}

int main ( int argc, char* argv[] )
{
  char buf[100]; //pw file에 id/pw 정보 읽어들이기
  std::cout << "running....\n";
  std::ifstream in("pw.txt");
  std::vector<std::string> vec;
  std::vector<std::string>::iterator iter;

  byte iv[ CryptoPP::AES::BLOCKSIZE ]; 
  int aesKeyLength = SHA256::DIGESTSIZE;  //key length 32 bytes = 256 bit key
  memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE ); 

  if (in.is_open()) {
    while (!in.eof()) {
   in.getline(buf,100);
   vec.push_back(buf);
    }
  } else {
    std::cout << "파일을 찾을 수 없습니다." << std::endl;
    return 0;
  }
  
  sort(vec.begin(), vec.end()); // ID/PW를 수월하게 찾기 위한(시간복잡도를 줄이기 위한) 소팅 수행

  try
    {
      // Create the socket
      ServerSocket server ( 30000 );

 
      while ( true )
   {

     ServerSocket new_sock;
     server.accept ( new_sock );
          
     std::string tempP, tempG, tempQ;

     new_sock >> tempP;
     new_sock >> tempG;
     new_sock >> tempQ;

     Integer p(tempP.c_str()); 
     Integer g(tempG.c_str());
     Integer q(tempQ.c_str());

     AutoSeededRandomPool rndB;
     DH dhB(p, q, g);

     SecByteBlock privB(dhB.PrivateKeyLength()); // Initialize private key b
     SecByteBlock pubB(dhB.PublicKeyLength()); // Initialize public key g^b
     SecByteBlock secretKeyB(dhB.AgreedValueLength()); // Initialize secret key g^ab

     // Generate a pair of integers for Bob. The public integer is forwarded to Alice.
     dhB.GenerateKeyPair(rndB, privB, pubB);
     
     //Initialize SecByteBlock to Integer
     Integer integerPubB;
     integerPubB.Decode(pubB.BytePtr(), pubB.SizeInBytes());  //public key g^b - A에게 전송할
     std::string strPubA;  //Client에게 받을 public key g^a
     new_sock << ToString(integerPubB); //클라이언트에게 줄 공유키 g^b
     new_sock >> strPubA; //클라이언트에서 받은 공유키 g^a 
     std::cout << "Public key g^b :: " << ToString(integerPubB) << "\n";
     std::cout << "Public key g^a :: " << strPubA << "\n";

     Integer intPubA(strPubA.c_str());

     SecByteBlock pubA;
     UnsignedIntegerToByteBlock(intPubA, pubA);

     if (!dhB.Agree(secretKeyB, privB, pubA)) std::cout << "client가 DH 인증에 실패하였습니다." << "\n";

     SecByteBlock key(SHA256::DIGESTSIZE);
     SHA256().CalculateDigest(key, secretKeyB, secretKeyB.size());

     try
       {
         while ( true )
      {
        std::string data, recvdata, base64decryptedciphertext, isCorrect = "";
        int number;
   
      ///////////////////////////////////////////////////////
        new_sock >> data;   //client에서 data받아옴

        //받은 id/pw base64복호화 및 AES_CBC Mode 복호화
        CryptoPP::StringSource(data, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink( base64decryptedciphertext)));

        CryptoPP::AES::Decryption aesDecryption (key, aesKeyLength);
        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption (aesDecryption, iv);

        CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(recvdata));
        stfDecryptor.Put(reinterpret_cast<const unsigned char*>(base64decryptedciphertext.c_str()), base64decryptedciphertext.size());
        stfDecryptor.MessageEnd();

        /*
        ******************************
        ********** 인증 과정 **********
        ******************************
         1. vector에 저장되어있는 string과 비교
         2. find 함수를 이용할것이고, 전에 소팅 완료 되어있는 vec를 가지고 client에서 받은 new_sock과 비교한다.
         3. 비교했을 때 iterator가 end를 가리키지 않는다면 일치하는 아이디/패스워드가 존재하는 것!
          4. 일치한다면 값을 보내주고, 아니라면 인증 실패 스트링을 client에 띄워준다. 
         5. 인증 실패 스트링을 띄워주기 위해서는, isCorrect에 false 문자를 넣어 보낸다.
        */
        recvdata.pop_back();

        iter = find(vec.begin(), vec.end(), recvdata);   // ID와 일치하는 PW가 존재하는지 확인
      
        //std::cout << *iter << "\n";

        if(iter == vec.end()) isCorrect = "false"; //존재하지 않는다면 FALSE
        else isCorrect = "true"; //존재한다면 TRUE

        /*
        ******************************
        ********** 값 전달 과정 **********
        ******************************
         1. number를 스캔한 후에 제곱한다.
         2. 제곱한 값을 to_string 함수를 이용하여 string형으로 변환시킨 후, new_sock을 통해 client로 값을 넘겨준다. 
        */
        if(isCorrect == "true") {
          std::cout << "인증에 성공하였습니다!\n";
          std::cout << "client에게 보낼 값을 입력하세요: ";
          scanf("%d",&number);   //number값 입력
          number*=number;
         
          new_sock << std::to_string(number);    //number 제곱한 값 string으로 넘겨줌
          //이 때, new_sock << 한 만큼 모두 합쳐져서 client에게 보내짐
        } else {
          new_sock << isCorrect; //인증에 실패하였음을 client에 알림
        }
      }
       }
     catch ( SocketException& ) {}

   }
    }
  catch ( SocketException& e )
    {
      std::cout << "Exception was caught:" << e.description() << "\nExiting.\n";
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
