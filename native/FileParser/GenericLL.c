#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include "GenericLL.h"


#pragma warning (disable: 4996)	
#pragma warning(disable:6031)


GenericLL* CreateGenericLL(void* data, int size) {
	GenericLL* newNode = (GenericLL*)calloc(1,sizeof(GenericLL));
	if (newNode) {
		newNode->next = NULL;
		newNode->data = calloc(size, sizeof(char));
		if (!newNode->data)
			return NULL;
		memcpy(newNode->data, data, size);
		return newNode;
	}
	return NULL;
}


int insert_end(GenericLL** end, void* data, int size)
{
	if (end == NULL) {
		printf("Invalid list end pointer\n");
		return 0;
	}
	//allocate memeory for new node
	GenericLL* newNode = CreateGenericLL(data, size);
	if (newNode) {
		if (*end) {
			(*end)->next = newNode;
			*end = newNode;
		}
		else {
			*end = newNode;
		}
		return 1;
	}
	else {
		printf("MALLOC PROBLEM %d\n", __LINE__);
		return 0;
	}
}


void printGenericLL(GenericLL* head, void (*fun)(void*))
{
	while (head != NULL) {
		(*fun)(head->data);
		head = head->next;
	}
}


void freeGenericLL(GenericLL* head) {
	GenericLL* tmp = NULL;
	while (head != NULL) {
		tmp = head;
		head = head->next;
		if (tmp->data)
			free(tmp->data);
		if (tmp)
			free(tmp);
	}
}


_declspec(noinline) void insertGenericLL(GenericLL** head, void* data, int size) {
	GenericLL* newNode = calloc(1, sizeof(GenericLL));
	if (newNode) {
		newNode->data = calloc(1, size);
		if (newNode->data)
			memcpy(newNode->data, data, size);
		newNode->next = NULL;
		if (*head == NULL) {
			*head = newNode;
			return;
		}

		// get last node
		GenericLL* lastNode = *head;
		while (lastNode->next != NULL) {
			lastNode = lastNode->next;
		}
		lastNode->next = newNode;
	}
	else {
		printf("MALLOC PROBLEM %d\n", __LINE__);
	}
}


char* StripString(char* str)
{
	size_t len = 0;
	char* frontp = str;
	char* endp = NULL;

	if (str == NULL) { return NULL; }
	if (str[0] == '\0') { return str; }

	len = strlen(str);
	endp = str + len;

	/* Move the front and back pointers to address the first non-whitespace
	 * characters from each end.
	 */
	while (isspace((unsigned char)*frontp)) { ++frontp; }
	if (endp != frontp)
	{
		while (isspace((unsigned char)*(--endp)) && endp != frontp) {}
	}

	if (frontp != str && endp == frontp)
		*str = '\0';
	else if (str + len - 1 != endp)
		*(endp + 1) = '\0';

	endp = str;
	if (frontp != str)
	{
		while (*frontp) { *endp++ = *frontp++; }
		*endp = '\0';
	}

	return str;
}

