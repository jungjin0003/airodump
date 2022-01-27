#include "airodump.hpp"

int main(int argc, char *argv[])
{
    system("clear");
    if (argc < 2)
    {
        std::cout << "syntax : airodump <interface>" << std::endl;
        std::cout << "sample : airodump mon0" << std::endl;
        return -1;
    }

    // while (true)
    // {
    //     struct winsize w;
    //     ioctl(0, TIOCGWINSZ, &w);

    //     printf("%d\n", w.ws_row);
    //     sleep(1);
    // }

    char *dev = argv[1];
    airodump airodump(dev);
    airodump.start();
    sleep(600);
}