#include "FileParser.h"
#include "FeatureExtractor/FeatureHeader.h"

#define MALWAREFULLFUNCSIZE 256

void freeTrustedCAtreeCert(struct Certificate* cert) {
	if (cert == NULL) {
		return; // Nothing to free
	}
	if (cert->Name)
		free(cert->Name);
	if (cert->SubjectRDN)
		free(cert->SubjectRDN);
	if (cert->SerialNumber)
		free(cert->SerialNumber);
	if (cert->Thumbprint)
		free(cert->Thumbprint);
	if (cert->IssuerName)
		free(cert->IssuerName);
	if (cert->IssuerRDN)
		free(cert->IssuerRDN);
	/*if (cert->ValidFrom)
		free(cert->ValidFrom);
	if (cert->ValidTo)
		free(cert->ValidTo);*/
	if (cert->SubjectPublicKeyInfo)
		free(cert->SubjectPublicKeyInfo);
	if (cert->SignatureValue)
		free(cert->SignatureValue);
	if (cert->tbsCertHashValue)
		free(cert->tbsCertHashValue);

	// Free the next certificate in the linked list
	freeTrustedCAtreeCert(cert->next);

	// Free the struct instance itself
	if (cert)
		free(cert);
}

void freeTrustedCAtree(struct Node_t* node) {
	if (node == NULL) {
		return;
		//printf("Valid ptr\n\n");
	}

	freeTrustedCAtree(node->left);
	freeTrustedCAtree(node->right);
	if (node->key) {
		//printf("%s ==> ", node->key);
		free(node->key);
	}
	if (node->value) {
		freeTrustedCAtreeCert(node->value);
		free(node->value);
		//printf("\n");
	}
	//if (node)
	//	free(node);
	//printf("\n\n");

}

void freeExtNode1(struct ExtNode* node) {
	if (node == NULL) {
		return; // Nothing to free
	}

	// Free MimeValue linked list
	struct MimeValue* mimeValue = node->MimeValue;
	while (mimeValue != NULL) {
		struct MimeValue* nextMimeValue = mimeValue->next;
		if (mimeValue->exttype)
			free(mimeValue->exttype);
		if (mimeValue->mimetype)
			free(mimeValue->mimetype);
		free(mimeValue);
		mimeValue = nextMimeValue;
	}

	// Free the nextLevel node
	if (node->nextLevel)
		freeExtNode1(node->nextLevel);


	// Free left and right nodes
	if (node->left)
		freeExtNode1(node->left);
	if (node->right)
		freeExtNode1(node->right);

	// Free the struct instance itself
	//if (node)
	//	free(node);
}


__declspec(noinline) void freeHashTableMalwareFullFunc(struct hashTableMalwareFullFunc* hashTable) {
	
	
	if (hashTable == NULL) {
		return; // Nothing to free
	}
	

	// Free each entry in the hash table
	for (int i = 0; i < MALWAREFULLFUNCSIZE; i++) {
		struct entryMalwareFullFunc* entry = hashTable->valueEntry[i];
		while (entry != NULL) {
			struct entryMalwareFullFunc* nextEntry = entry->next;
			if (entry->key)
				free(entry->key);
			if (entry)
				free(entry);
			entry = nextEntry;
		}
	}
	
	
	// Free the struct instance itself
	//if (hashTable)
	//	free(hashTable);

}


__declspec(noinline) int freePEParserStruct(Tree_t** TrustedCAtree, struct ExtNode** root, struct hashTableMalwareFullFunc* mapMalwareFullFunc) {
	
	
	// Free TrustedCertifcate from the AVL Tree
	if (*TrustedCAtree) {
		if ((*TrustedCAtree)->root)
			freeTrustedCAtree((*TrustedCAtree)->root);
		free(*TrustedCAtree);
	}


	// Free File Ext And Mime Type from the Trie+AVL Tree
	if (*root) {
		freeExtNode1(*root);
	}


	// Free Import Function Model Data From HashMap 
	if (mapMalwareFullFunc) {
		freeHashTableMalwareFullFunc(mapMalwareFullFunc);
	}
	return EXIT_SUCCESS;
}

