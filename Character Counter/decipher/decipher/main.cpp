//  Created by Sam Pickell on 1/29/20.
//  Copyright © 2020 Sam Pickell. All rights reserved.
//

#include <iostream>
#include <string>

int main(int argc, const char * argv[])
{
    std::string cipher = "NTCGPDOPANFLHJINTOOFITOVJHJCTMMHIHEMTCPFDWTSOFSHTOGFWTETTJJTBTOOFSZOVEOCHCVCHPJHOCGTOHNQMTOCNTCGPDCGFCSTQMFBTOFBGFSFBCTSHJCGTQMFHJCTYCXHCGFAHYTDDHAATSTJCBGFSFBCTSHJCGTBHQGTSCTYCCGHONTCGPDQSTOTSWTOCGTMTCCTSASTRVTJBZHJCGTQMFHJCTYCFJDOPPJTBFJOTFSBGAPSCGTQMFHJCTYCASPNFIHWTJBHQGTSCTYCEZBPNQFSHJICGTASTRVTJBZPATFBGMTCCTSFIFHJOCCGTLJPXJBPNNPJASTRVTJBZHJCGTVJDTSMZHJIMFJIVFIT";
    
    for(int i = 0; i < cipher.length(); i++)
    {
        char c = cipher.at(i);
        
        if(c == 'A')
        {
            c = 'F';
        }
        else if(c == 'B')
        {
            c = 'C';
        }
        else if(c == 'C')
        {
            c = 'T';
        }
        else if(c == 'D')
        {
            c = 'D';
        }
        else if(c == 'E')
        {
            c = 'B';
        }
        else if(c == 'F')
        {
            c = 'A';
        }
        else if(c == 'G')
        {
            c = 'H';
        }
        else if(c == 'H')
        {
            c = 'I';
        }
        else if(c == 'I')
        {
            c = 'G';
        }
        else if(c == 'J')
        {
            c = 'N';
        }
        else if(c == 'L')
        {
            c = 'K';
        }
        else if(c == 'M')
        {
            c = 'L';
        }
        else if(c == 'N')
        {
            c = 'M';
        }
        else if(c == 'O')
        {
            c = 'S';
        }
        else if(c == 'P')
        {
            c = 'O';
        }
        else if(c == 'Q')
        {
            c = 'P';
        }
        else if(c == 'R')
        {
            c = 'Q';
        }
        else if(c == 'S')
        {
            c = 'R';
        }
        else if(c == 'T')
        {
            c = 'E';
        }
        else if(c == 'V')
        {
            c = 'U';
        }
        else if(c == 'W')
        {
            c = 'V';
        }
        else if(c == 'X')
        {
            c = 'W';
        }
        else if(c == 'Y')
        {
            c = 'X';
        }
        else if(c == 'Z')
        {
            c = 'Y';
        }
        else
        {
            std::cout << "Error. Value originally: " << c << std::endl;
            c = '!';
        }
        
        cipher.at(i) = c;
    }
    
    std::cout << "Decyphered message: " << std::endl;
    std::cout << cipher << std::endl;
}
