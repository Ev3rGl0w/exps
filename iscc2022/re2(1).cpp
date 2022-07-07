#include <iostream>
using namespace std;

int main(int argc,char *argv[]) {
string flag = "ISCC{012345678901}";
int key[4] = {'I', 'S', 'C', 'C'};
int n = 18;
      int flagI[18] = {
      -542422941,
      -1391350689,
      -1177494541,
      1550251653,
      1737963831,
      327027107,
      -909352636,
      1426868886,
      1330090530,
      -1060600897,
      1100812917,
      1925272733,
      1865409304,
      -415547275,
      -45283816,
      -524151296,
      -61665969,
      -794246572,
      };
      
      rounds = 52 / n + 6; // 8
      static1 = rounds * -0x61C88647;
      
      int y = flagI[0];
      for (; rounds--;) {
        int static2 = (static1 >> 2) & 3; // 固定值
        
        for (int i=n-1; i>=0; i--) {
          int z = flagI[(i + n - 1)%n];
          flagI[i] -= ((y ^ static1) + (z ^ key[static2 ^ (i & 3)])) ^ (((4 * y) ^ (z >> 5)) + ((y >> 3) ^ (16 * z)));
          y = flagI[i];
          }
          
          static1 += 0x61C88647; // 固定值
          }
          for (int i = 0; i < n; ++i)
            cout << (char)flagI[i];
          cout << endl;
          return 0;
}