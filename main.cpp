#include <iostream>
#include <getopt.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>




using namespace std;


void help()
{
    cerr << "Run the program with arguments -i or -r."  << endl;
}


int check_params(int argc, char *argv[])
{
    string promena;

    if(argc < 2)
    {

    }
    else if(argc == 3)
    {
        while (( opt = getopt(argc, argv, "ir")) != -1)
        {
            switch (opt)
            {
                case 'a':
                   argv[optind];
                    ///
                    break;
                case 'm':

                    ///
                    break;
            }
        }
    }
    else
    {
        help();
        exit(0);
    }


}

int main(int argc, char *argv[])
{
    int result = check_params(argc, argv);
    cout << "Hello, World!" << endl;
    return 0;
}