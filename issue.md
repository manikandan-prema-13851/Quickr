* crash-1: SetHashDetail() => HCRYPTPROV* hprov,  release content many times using CryptReleaseContext
* crash-2: GetSignerCertificateInfo() => SignDataChainStart, freed before iteration
* crash-3: cmalwaredetails() => szName null terminator check need to add


* debug support 
    heap corruption size_t to int (mismatch data)
    stack variable returns.   This fix ensures safe memory management and avoids potential crashes or data corruption.

* extras
#pragma warning(error : 4101) // Treat C4101 as an error
Unchecked Memory Allocations
Double-Free or Dangling Pointers
Incorrect or Missing Bounds Checking
Improper Cleanup in Error Paths
Potential Overflows in sprintf
Invalid Pointer Access in Cleanup Loops
Use After Free
