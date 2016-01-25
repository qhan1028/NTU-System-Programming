#include <cstdio>
#include <cstring>
#include <vector>

#define SMAX 100000002
#define UL 0
#define U 1
#define L 2

#define ERR 0
#define UL_DR 1
#define UL_R 2
#define UL_D 3
#define U_D 4
#define U_R 5
#define U_DR 6
#define L_DR 7
#define L_R 8
#define L_D 9

using namespace std;
typedef vector<int> VI;
char *in1 = new char[SMAX];
char *in2 = new char[SMAX];

class Table {
public:
	Table(){
		num = 0;
		dir = 0;
		ispath = false;
	};
	int num;
	int dir;
	bool ispath;
};

int findCase(Table *table[], int i, int j)
{
	if (i > 0 && table[i-1][j].ispath) {
		if (table[i+1][j].ispath) return U_D;
		if (table[i][j+1].ispath) return U_R;
		return U_DR;
	}
	else if (j > 0 && table[i][j-1].ispath) {
		if (table[i][j+1].ispath) return L_R;
		if (table[i+1][j].ispath) return L_D;
		return L_DR;
	}
	else if (table[i-1][j-1].ispath) {
		if (table[i][j+1].ispath) return UL_R;
		if (table[i+1][j].ispath) return UL_D;
		return UL_DR;
	}
	return ERR;
}

void assign(Table &pos, int n, int d, bool p) 
{
	pos.num = n;
	pos.dir = d;
	pos.ispath = p;
}

void findSize(FILE *file1, FILE *file2, int &row, int &col, VI &len1, VI &len2)
{
	while(!feof(file1) || !feof(file2)) {
		fgets(in1, SMAX, file1);
		fgets(in2, SMAX, file2);
		if (!feof(file1)) { row++; len1.push_back(strlen(in1));}
		if (!feof(file2)) { col++; len2.push_back(strlen(in2));}
	}
}

long getSum(int n, VI &v) 
{
	long sum = 0;
	for(int i = 1 ; i < n ; i++) {
		sum += v[i];
	} return sum;
}

bool cmpLine(FILE *file1, FILE *file2, int i, int j, VI &len1, VI &len2) 
{
	int c1, c2;
	if(len1[i] == len2[j]) {
		fseek(file1, getSum(i, len1), SEEK_SET);
		fseek(file2, getSum(j, len2), SEEK_SET);
		for (int k = 0 ; k < len1[i] ; k++) {
			c1 = fgetc(file1);
			c2 = fgetc(file2);
			if(c1 != c2) return false;
		}
		return true;
	}
	else return false;
}

int main(int argc, const char *argv[]) 
{
	FILE *file1 = fopen(argv[1], "r");
	FILE *file2 = fopen(argv[2], "r");

	// find the size of table
	int row = 0, col = 0;
	VI len1, len2;
	len1.push_back(0); 
	len2.push_back(0);
	findSize(file1, file2, row, col, len1, len2);
	
	// allocating 2d array
	// initialize first row
	Table **table = new Table*[row+2];
	table[0] = new Table[col+2];
	for (int k = 0 ; k < col+2 ; k++) assign(table[0][k], 0, L, false);
	assign(table[0][0], 0, UL, true);

	// start to build the table
	int i = 1, j = 1;
	while(i <= row) {
		table[i] = new Table[col+2];
		assign(table[i][0], 0, U, false);
		j = 1;
		while(j <= col) {	
			if (cmpLine(file1, file2, i, j, len1, len2)) {
				assign(table[i][j], table[i-1][j-1].num+1, UL, false);
			} else {
				if (table[i][j-1].num >= table[i-1][j].num) {
					assign(table[i][j], table[i][j-1].num, L, false);
				} else assign(table[i][j], table[i-1][j].num, U, false);
			}
			j++;
		}
		i++;
	}
	i--; j--;
	table[row+1] = new Table[col+2];

	// find path
	while(i >= 0 && j >= 0) {
		table[i][j].ispath = true;
		if(table[i][j].dir == UL) {
			if (i == 0 && j == 0) break;
			else if (i == row && j == col) {
				i--;j--;
			}
			else if (i == row || j == col) {
				if (table[i-1][j-1].dir == UL) {
					i--;j--;
				}
				else j--;
			}
			else if(table[i-1][j-1].dir == UL || table[i+1][j+1].dir == UL) {
				i--;j--;
			} 
			else j--;
		} 
		else if(table[i][j].dir == L) j--;
		else if(table[i][j].dir == U) i--;
	}
/*
	// print table
	for (int k = 0 ; k <= row ; k++) {
		for (int l = 0 ; l <= col ; l++) {
			if (table[k][l].ispath) printf("X");
			else printf(" ");
			if (table[k][l].dir == U) printf("|");
			if (table[k][l].dir == UL) printf("\\");
			if (table[k][l].dir == L) printf("-");
			printf("%d ", table[k][l].num);
		}
		printf("\n");
	}
*/
	// traverse the table
	i = j = 0;
	int buffer2 = 0;
	FILE *out = fopen(argv[3], "wb");
	fseek(file1, 0, SEEK_SET);
	fseek(file2, 0, SEEK_SET);
	if(table[i+1][j].ispath) {
		fprintf(out, ">>>>>>>>>> %s\n", argv[1]);
		i++;
	} else if(table[i][j+1].ispath) {
		fprintf(out, ">>>>>>>>>> %s\n", argv[1]);
		j++;
	} else if(table[i+1][j+1].ispath) {
		i++;j++;
	}
	while(i <= row && j <= col) {
		switch(findCase(table, i, j)) {
			case UL_DR : 
				fgets(in1, SMAX, file1);
				fgets(in2, SMAX, file2);
				fprintf(out, "%s", in1);
				i++;j++;break;
			case UL_R :
				fgets(in1, SMAX, file1);
				fgets(in2, SMAX, file2);
				fprintf(out, "%s", in1);
				fprintf(out, ">>>>>>>>>> %s\n", argv[1]);
				j++;break;
			case UL_D :
				fgets(in1, SMAX, file1);
				fgets(in2, SMAX, file2);
				fprintf(out, "%s", in1);
				fprintf(out, ">>>>>>>>>> %s\n", argv[1]);
				i++;break;
			case U_D :
				fgets(in1, SMAX, file1);
				fprintf(out, "%s", in1);
				i++;break;
			case L_R :
				buffer2++; j++; break;
			case U_R :
				fgets(in1, SMAX, file1);
				fprintf(out, "%s", in1);
				j++;break;
			case L_D :
				buffer2++; i++; break;
			case U_DR :
				fgets(in1, SMAX, file1); fprintf(out, "%s", in1);
				fprintf(out, "========== %s\n", argv[2]);
				if (buffer2 > 0) {
					for (int k = 0 ; k < buffer2 ; k++) {
						fgets(in2, SMAX, file2);
						fprintf(out, "%s", in2);
					}
					buffer2 = 0;
				}
				fprintf(out, "<<<<<<<<<<\n");
				i++;j++;break;
			case L_DR :
				buffer2++;
				fprintf(out, "========== %s\n", argv[2]);
				if (buffer2 > 0) {
					for (int k = 0 ; k < buffer2 ; k++) {
						fgets(in2, SMAX, file2);
						fprintf(out, "%s", in2);
					}
					buffer2 = 0;
				}
				fprintf(out, "<<<<<<<<<<\n");
				i++;j++;break;
			default :
				fprintf(out, "wrong path\n");
		}
	}
	fclose(file1);
	fclose(file2);
	fclose(out);
	for (int k = 0 ; k < col+2 ; k++) delete [] table[k];
	delete [] table;
	return 0;
}
