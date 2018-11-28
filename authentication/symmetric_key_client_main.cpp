#include "ClientSocket.h"
#include "SocketException.h"
#include <iostream>
#include <string>

#include "cryptopp/modes.h" //Crypto++
#include "cryptopp/des.h" 
#include "cryptopp/filters.h" 
#include "cryptopp/base64.h" 

int main ( int argc, char* argv[] )
{

  byte key [CryptoPP::DES::DEFAULT_KEYLENGTH];
  memset(key, 0x00, CryptoPP::DES::DEFAULT_KEYLENGTH);

  try
    {

      ClientSocket client_socket ( "localhost", 30000 );

      std::string reply;

      try
	{
	  char tmp[101];
	  std::string userInfo, sendInfo, base64encodedciphertext; //처음 CLIENT가 쓰는 유저 INFO 
	  std::cout << "username: ";
	  scanf("%s",tmp); userInfo = tmp;

	  userInfo.append("\t");

	  std::cout << "password: ";
	  scanf("%s",tmp); userInfo.append(tmp);
	  
	  CryptoPP::DES::Encryption desEncryption (key, CryptoPP::DES::DEFAULT_KEYLENGTH);
	  CryptoPP::ECB_Mode_ExternalCipher::Encryption ecbEncryption (desEncryption);

	  CryptoPP::StreamTransformationFilter stfEncryptor(ecbEncryption, new CryptoPP::StringSink(sendInfo));

	  stfEncryptor.Put(reinterpret_cast<const unsigned char*>(userInfo.c_str()), userInfo.length()+1);
	  stfEncryptor.MessageEnd();

	  CryptoPP::StringSource(sendInfo, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64encodedciphertext)));
    
	  //client_socket에 들어간 id, pw를 Server에 보냄
	  client_socket << base64encodedciphertext;
    
	  //Server에서 보낸 제곱값 받음
	  client_socket >> reply;
	}
      catch ( SocketException& ) {}

      if(reply == "false" || reply == "falsefalse") {
	std::cout << "인증 실패!" << "\n";
	return 0;
      }
      std::cout << "We received this response from the server: " << reply << "\n";

    }
  catch ( SocketException& e )
    {
      std::cout << "Exception was caught:" << e.description() << "\n";
    }

  return 0;
}
