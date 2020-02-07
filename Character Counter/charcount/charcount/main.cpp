//  Created by Sam Pickell on 1/29/20.
//  Copyright © 2020 Sam Pickell. All rights reserved.
//

#include <iostream>
#include <string>

int main(int argc, const char * argv[])
{
    std::string cipher = "NTCGPDOPANFLHJINTOOFITOVJHJCTMMHIHEMTCPFDWTSOFSHTOGFWTETTJJTBTOOFSZOVEOCHCVCHPJHOCGTOHNQMTOCNTCGPDCGFCSTQMFBTOFBGFSFBCTSHJCGTQMFHJCTYCXHCGFAHYTDDHAATSTJCBGFSFBCTSHJCGTBHQGTSCTYCCGHONTCGPDQSTOTSWTOCGTMTCCTSASTRVTJBZHJCGTQMFHJCTYCFJDOPPJTBFJOTFSBGAPSCGTQMFHJCTYCASPNFIHWTJBHQGTSCTYCEZBPNQFSHJICGTASTRVTJBZPATFBGMTCCTSFIFHJOCCGTLJPXJBPNNPJASTRVTJBZHJCGTVJDTSMZHJIMFJIVFIT";
    
    std::cout << "String size: " << cipher.length() << std::endl;
    std::cout << std::endl;
    
    std::cout << "Character frequency: " << std::endl;
    
    for(int i = 0; i < 26; i++)
    {
        char c = 'A' + i;
        double counter = 0.0;
        
        
        for(int j = 0; j < cipher.length(); j++)
        {
            if(cipher.at(j) == c)
            {
                counter++;
            }
        }
        
        std::cout << c << ": " << counter/cipher.length() << std::endl;
    }
}
