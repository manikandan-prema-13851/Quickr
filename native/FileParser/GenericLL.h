
#ifndef GENERIC_LL_H
#define GENERIC_LL_H

typedef struct GenericLL {

	void* data;
	struct  GenericLL* next;

}GenericLL;

GenericLL* CreateGenericLL(void* data, int size);
int insert_end(GenericLL** end, void* data, int size);
void printGenericLL(GenericLL* head, void (*fun)(void*));
void freeGenericLL(GenericLL* head);
void insertGenericLL(GenericLL** head, void* data, int size);

char* StripString(char* s);
#endif // !GENERIC_LL_H
