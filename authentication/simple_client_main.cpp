#include "ClientSocket.h"
#include "SocketException.h"
#include <iostream>
#include <string>

int main ( int argc, char* argv[] )
{
  try
    {

      ClientSocket client_socket ( "localhost", 30000 );

      std::string reply;

      try
   {
     char tmp[101];
     std::string userInfo;
     std::cout << "username: ";
     scanf("%s",tmp); userInfo = tmp;

     userInfo.append("\t");

     std::cout << "password: ";
     scanf("%s",tmp); userInfo.append(tmp);

     //client_socket에 들어간 id, pw를 Server에 보냄
     client_socket << userInfo;
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
